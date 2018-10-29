##! MG algorithm, SMED extension, Jim Mellander, ESNet

# $Id: mg.bro,v 1.2 2018/10/29 19:04:03 melland Exp melland $

# Copyright (c) 1995-2018, The Regents of the University of California
# through the Lawrence Berkeley National Laboratory and the
# International Computer Science Institute. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
# 
# (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
# 
# (3) Neither the name of the University of California, Lawrence Berkeley
#     National Laboratory, U.S. Dept. of Energy, International Computer
#     Science Institute, nor the names of contributors may be used to endorse
#     or promote products derived from this software without specific prior
#     written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# 
# Note that some files in the distribution may carry their own copyright
# notices.

# This implements a variant of what is commonly known as the "Misra-Gries algorithm".
#  Variants of it were discovered and rediscovered and redesigned several times over the years:
#
#   "Finding repeated elements", Misra, Gries, 1982
#   "Frequency estimation of Internet packet streams with limited space", Demaine, Lopez-Ortiz, Munro, 2002
#   "A simple algorithm for finding frequent elements in streams and bags", Karp, Shenker, Papadimitriou, 2003
#   "Efficient Computation of Frequent and Top-k Elements in Data Streams", Metwally, Agrawal, Abbadi, 2006
#
# The current algorithm is based on:
#
#   "A High-Performance Algorithm for Identifying Frequent Items in Data Streams",
#       Anderson, Bevin, Lang, Liberty, Rhodes, Thaler, 2017
#
# Algorithms 4&5 of https://conferences.sigcomm.org/imc/2017/papers/imc17-final255.pdf
#  See: https://github.com/DataSketches/sketches-core/blob/master/src/main/java/com/yahoo/sketches/frequencies/ItemsSketch.java
#   for the authors' Java implementation
#   ReversePurgeItemHashMap.java has the purge (DecrementCounters in the paper) implementation
#
# See algorithm 4 in the paper for the basic concept.
#  The UpdateCounters() algorithm as presented in the paper is a "stop the world" implementation, that
#  is probably not the best choice for a realtime application like Bro.  So, this implementation uses
#  a lazy delete algorithm.  Our lazy algorithm is as follows:
#
#  First, we note that when UpdateCounters() is called, we actually only need to free up one slot,
#   for the current item.
#  So, we look for entries that haven't had the median applied updating the counters until we find a
#   candidate for deletion and use that slot.  When another slot is needed, we continue thru the
#   table of entries looking for the next candidate for deletion.  If we reach the end, we compute
#   a new median, and start again at the beginning.  On average, we only expect to scan a few slots
#   until we find one to be reused....  Simple, easy!  right?
#
#  Well, a complication arises that table entries *after* where we are currently scanning may
#   be updated in between freeing up slots, thus making the value different than would be under
#   the original algorithm.  To avoid this, we use two tables, one has post-median values,
#   and one with pre-median values.  We go thru the pre-median table, updating, and moving to
#   the post median table if the value is > median.  If not, the entry is deleted, and the
#   new entry is added to the post-median table (after application of the median).  When a
#   new median is calculated, all the entries are moved to the pre-median table for the
#   next round.  Each update, we amortize the cost by moving a few entries from pre to
#   post median, as well as via a periodically scheduled event.
#
#   At the end of the epoch, upon composing the final result, entries still marked with the
#   prior generation will have the final median subtracted.
#
#  A merge step occurs in a cluster context, where tables from multiple workers are merged by
#   simply using the regular code above to update one table from the other, taking into account
#   that some of the entries to be updated have not been modified in our lazy algorithm.
#   For completeness, we can return the table in sorted order, or at least the TopK.
#

@load base/frameworks/sumstats/main

module SumStats;

export {
	redef enum Calculation += {
		## Keep Heavy Hitters key & amount from input
		## stream.
		MG
	};

	redef record Reducer += {
		## Table size
		#mg_tbl_sz: count &default=256;
		#mg_tbl_sz: count &default=64;
		#mg_tbl_sz: count &default=16;
		#mg_tbl_sz: count &default=1024;
		mg_tbl_sz: count &default=8192;
		## Sample count for median calculation
		mg_L: count &optional;
	};

	redef record ResultVal += {
		## This is the table in which the samples are maintained.

		# We use 3 structures:
		#  mg_tbl: key/value of observation
		#  mg_tbl_pre_median: key/value of observations prior
		#                     to median applied
		#  mg_order: 0 to mg_tbl_sz-1 with keys for median calc
		#   (This is a table[count] rather than a vector, due
		#    to the desire to iterate in non-sequential order)
		
		mg_tbl: table[string] of double &optional;
		mg_tbl_pre_median: table[string] of double &optional;
		mg_order: table[count] of string &optional;

		mg_grand_total: double &default=0.0;
		mg_offset: double &default=0.0;	# See 2.3.1 in the paper

		## Table size
		mg_tbl_sz: count &optional;
		## Sample count for median calculation
		mg_L: count &optional;
		## Current median
		mg_median: double &default=0.0;
	};
}

#*********** DEBUG **************
function printit(s:string)
	{
	local y=fmt("%.6f %.6f %s MG %s",current_time(),network_time(),Cluster::node,s);
	Reporter::warning(y);
	}
#******************************

hook init_resultval_hook(r: Reducer, rv: ResultVal)
	{
	if ( MG in r$apply )
		{
		rv$mg_tbl = table();
		rv$mg_tbl_pre_median = table();
		rv$mg_order = table();
		if (! rv?$mg_tbl_sz)	rv$mg_tbl_sz = r$mg_tbl_sz;
		#  In the java code, the median sample size is the lesser of 1024 &
		#   .75*mg_tbl_sz, which seems unreasonably high,
		#   but the authors are looking at very large tables.
		#  The paper indicates that it should be O(log2(mg_tbl_sz)),
		#   so we use 4*log2(mg_tbl_sz).

		if (! rv?$mg_L)
			rv$mg_L = r?$mg_L ? r$mg_L :
				double_to_count(4.0*(ln(rv$mg_tbl_sz)/ln(2.0) + .01));
		# Shouldn't happen (famous last words) - this ensures
		#  that we won't have an infinite loop when selecting a median.
		if (rv$mg_L > rv$mg_tbl_sz / 2)	rv$mg_L = rv$mg_tbl_sz / 2;
		# Ensure odd
		if (rv$mg_L % 2 == 0)	++rv$mg_L;
		}
	}

function MG_lazy(rv: ResultVal): bool
	{
	# Incremental lazy algorithm.
	#  Move a few entries from pre-median to main table.
	#  If an entry is <= median, it is just deleted, freeing up a
	#  slot.
	if (|rv$mg_tbl_pre_median| == 0)
		return F;
	local slot2delete: set[string];
	#printit(fmt("Start MG_lazy |mg_tbl|=%d, |mg_tbl_pre_median|=%d",|rv$mg_tbl|,|rv$mg_tbl_pre_median|));
	local limit = 10;
	for (k9 in rv$mg_tbl_pre_median)
		{
		local v2 = rv$mg_tbl_pre_median[k9] - rv$mg_median;
		if (v2 > 0.0)
			{
			rv$mg_tbl[k9] = v2;
			rv$mg_order[|rv$mg_order|] = k9;
			}
		add slot2delete[k9];
		if (--limit == 0)	break;
		}
	if (|slot2delete| == |rv$mg_tbl_pre_median|)
		rv$mg_tbl_pre_median = table();
	else for (k9 in slot2delete)
		delete rv$mg_tbl_pre_median[k9];
	#printit(fmt("End MG_lazy |mg_tbl|=%d, |mg_tbl_pre_median|=%d",|rv$mg_tbl|,|rv$mg_tbl_pre_median|));

	return (|rv$mg_tbl_pre_median| > 0);
	}

# Periodic event for lazy delete
event MG_periodic(rv: ResultVal)
	{
	# Execute lazy delete, if still more, reschedule
	if (MG_lazy(rv))	schedule 10 msec { MG_periodic(rv) };
	}

# This is the main function that adds/updates an entry to the table,
#  as well as purging entries that are stale using our lazy algorithm.

function MG_Update(rv: ResultVal, key: string, val: double)
	{
	if (val <= 0.0)	return;
	local tt = current_time();
	++rv$sample_elements;
	rv$mg_grand_total += val;
	local mg_tbl = rv$mg_tbl;
	local mg_order = rv$mg_order;

	# Lazy delete
	MG_lazy(rv);

	# If key in main table, update amount
	if (key in mg_tbl)
		{
		mg_tbl[key] += val;
		#printit(fmt("%s %g, time=%g",key,val,current_time()-tt));
		return;
		}

	# If key in premedian table, apply median & move to main table
	if (key in rv$mg_tbl_pre_median)
		{
		if (rv$mg_tbl_pre_median[key] <= rv$mg_median)
			mg_tbl[key] = val;
		else
			mg_tbl[key] = rv$mg_tbl_pre_median[key] - rv$mg_median + val;
		mg_order[|mg_order|] = key;
		delete rv$mg_tbl_pre_median[key];
		#printit(fmt("%s %g, time=%g",key,val,current_time()-tt));
		return;
		}

	# The key doesn't exist, but can add if the table isn't full.
	if (|mg_tbl|+|rv$mg_tbl_pre_median| < rv$mg_tbl_sz)
		{
		mg_tbl[key] = val;
		mg_order[|mg_order|] = key;
		#printit(fmt("%s %g, time=%g",key,val,current_time()-tt));
		return;
		}

	# Here, the key doesn't exist in the table, and the table is full,
	#  so we need to purge space to possibly add the key.
	# This is a lazy delete variant of the DecrementCounters() function in the paper.
	#

	local keep_going = T;
	local mg_tbl_sz = rv$mg_tbl_sz;
	#local c = 0; #******************************

	while (keep_going)
		{
		# If median is null, compute a new median
		#  this only occurs when we've gone thru
		#  the entire table, (or the first time thru)
		#  so the values have all had the previous
		#  median subtracted.

		if (rv$mg_median == 0.0)
			{
			local L = rv$mg_L;

			#printit("Start median calc");
			# Select L random entries to use for median calc
			local probes:set[count] = set();
			while (|probes| < L)	add probes[rand(mg_tbl_sz)];

			# Put values into vector and sort
			local sortme: vector of double = vector();
			#print rv$mg_tbl;	#********************************
			#print rv$mg_order;
			for (k in probes)	sortme[|sortme|] = mg_tbl[rv$mg_order[k]];
			sort(sortme,
				function(a:double, b:double): int { if (a > b) return 1; if (a < b) return -1; return 0; });

			# Find median (c* in the paper)
			rv$mg_median = sortme[L/2];

			#printit("End median calc");
			# Total of all medians (section 2.3.1 in the paper)
			rv$mg_offset += rv$mg_median;

			# ************************************
			if (F)
				{
				local a = 0;
				local b = 0;
				for (k0 in rv$mg_tbl)
					{
					if (rv$mg_tbl[k0] > rv$mg_median)	++a;
					else ++b;
					}
				printit(fmt("Median, above %d, below %d", a, b));
				}
			# ************************************

			# Move all current entries to pre_median
			rv$mg_tbl_pre_median = rv$mg_tbl;
			rv$mg_tbl = table();
			rv$mg_order = table();

			# & schedule a periodic lazy delete
			schedule 1 msec { MG_periodic(rv) };

			# We computed a new median, so check against it, and skip if less.
			# (we need to make sure we're using the current median,
			#  which is why this test is here)
			val -= rv$mg_median;	# Algorithm 4, line 14
			if (val <= 0.0)
				break;
			}

		# Here, we search for a slot for our key/value

		local slot2delete: set[string] = set();
		for (k2 in rv$mg_tbl_pre_median)
			{
			local val1 = rv$mg_tbl_pre_median[k2] - rv$mg_median;
			add slot2delete[k2];	# This slot will be deleted one way or another
			#++c;	#*********************************
			#  See if slot can be used
			if (val1 <= 0.0)
				{
				# Yes, add our entry
				rv$mg_tbl[key] = val;
				rv$mg_order[|rv$mg_order|] = key;
				keep_going = F;
				break;
				}

			# If not, move to main table & decrement by median, per paper.
			else
				{
				rv$mg_tbl[k2] = val1;
				rv$mg_order[|rv$mg_order|] = k2;
				}
			}

		if (|slot2delete| == |rv$mg_tbl_pre_median|)
			rv$mg_tbl_pre_median = table();
		else for (k2 in slot2delete)
			delete rv$mg_tbl_pre_median[k2];

		# When we reach end, reset to beginning & force new median calc
		if (|rv$mg_tbl_pre_median| == 0)
			rv$mg_median = 0.0;

		}	# keep_going?

	#printit(fmt("%s %g, time=%g",key,val,current_time()-tt));
	#printit(fmt("Entries examined %d", c));

	# Lazy delete
	MG_lazy(rv);

	# Done!
	}

hook register_observe_plugins()
	{
	register_observe_plugin(MG, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		MG_Update(rv, obs$str, val);
		});
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{

	local res1: ResultVal;
	local res2: ResultVal;

	if (rv1?$mg_tbl)
		if (rv2?$mg_tbl)
			{
			# Larger of 2 tables will be the result table
			if (|rv1$mg_tbl|+|rv1$mg_tbl_pre_median| > |rv2$mg_tbl|+|rv2$mg_tbl_pre_median|)
				{
				res1 = rv1;
				res2 = rv2;
				}
			else
				{
				res1 = rv2;
				res2 = rv1;
				}
			}
		else res1 = rv1;
	else if (rv2?$mg_tbl)
		res1 = rv2;
	else
		return;

	# At least one of the two results is present, lets go

	# Copy 1st one
	result$mg_tbl = res1$mg_tbl;
	result$mg_tbl_pre_median = res1$mg_tbl_pre_median;
	result$mg_order = res1$mg_order;
	result$mg_tbl_sz = res1$mg_tbl_sz;
	result$mg_L = res1$mg_L;
	result$mg_median = res1$mg_median;
	result$mg_offset = res1$mg_offset;
	local grand_total = res1$mg_grand_total;
	local sample_elements = res1$sample_elements;

	# If there's a 2nd one, we merge into the copy
	#  of the 1st one.
	if (res2?$mg_tbl)
		{
		# Based on the implementation by the authors of the paper, the combined offset is the sum
		#  (which may change, as we add to the result table)
		result$mg_offset += res2$mg_offset;
		local tl1 = |result$mg_tbl| + |result$mg_tbl_pre_median|;
		local tl2 = |rv2$mg_tbl| + |rv2$mg_tbl_pre_median|;

		# Make result table size to be sum of both sizes
		result$mg_tbl_sz = tl1 + tl2;
		# ... clamp to 5x the smaller table (res2)
		local small = 5 * tl2;
		if (result$mg_tbl_sz > small)
			{
			result$mg_tbl_sz = small;
			# ... but make sure at least the current table size
			if (result$mg_tbl_sz < tl1)
				result$mg_tbl_sz = tl1;
			}

		grand_total += res2$mg_grand_total;
		sample_elements += res2$sample_elements;
		local mg_median = res2$mg_median;
		local mg_tbl = res2$mg_tbl;
		local mg_order = res2$mg_order;
		local mg_tbl_pre_median = res2$mg_tbl_pre_median;

		# Now go thru the 2nd table, and merge into the first..
		#  We iterate a different way, see Note to section 3.2
		#   in the paper.
		local key: string;
		local key1: count;
		for (key1 in mg_order)
			{
			key = mg_order[key1];
			MG_Update(result, key, mg_tbl[key]);
			}

		# And take care of non applied medians
		#  (MG_Update rejects negative values, so we don't need to check)
		for (key in mg_tbl_pre_median)
			MG_Update(result, key, mg_tbl_pre_median[key] - mg_median);

		# Here we clear res2$mg_tbl_pre_median, which
		#  prevents future periodic MG_lazy() calls
		#  to res2, which is no longer needed.
		# Might as well free up the memory for the
		#  main table, too.
		# (This is probably not needed)
		res2$mg_tbl = table();
		res2$mg_order = table();
		res2$mg_tbl_pre_median = table();

		}

	# Now fixup grand total
	result$mg_grand_total = grand_total;
	#  & total samples
	result$sample_elements = sample_elements;
	#  & trim result table
	result$mg_tbl_sz = |result$mg_tbl| + |result$mg_tbl_pre_median|;

	# Might as well do a lazy step
	MG_lazy(result);

	}

#
# TopK sort of table for presentation
#
# The easy way is to just use the builtin sort, but that requires sorting
#  everything despite knowing we're throwing away most of it.
# A TopK sort can be done with a minheap of K size.  Once its been filled
#  with the first K entries, we compare entries to the root.  If entry > root
#  we replace the root with our new value & rebalance.  At the end, the
#  entries are peeled off to fill the return table, back to front.
#

type retrec: record {key:string; val:double;};

export {

	global MG_TopK: function (result: ResultVal, topk: count): vector of retrec;
	}

#
# These 2 functions are a minheap implementation of retrec type
#
# References:
#   http://en.wikipedia.org/wiki/Binary_heap
#   http://www.sbhatnagar.com/SourceCode/pqueue.html
#
# The operations:
#
#  pqinsert(q,k) - insert to queue q, key k
#  pqremove(q) - returns top item of queue, and removes it from the queue
#
# q should be initialized as an empty table
#
# the root of the queue is q[1], unless the queue is empty, so the
#  queue can be inspected easily.
#
#  The size of the queue dynamically changes, due to bro's table
#    implementation.
#
#

function pqinsert(q: table[count] of retrec, k: retrec)
	{
        local i = |q| + 1;
	local kval = k$val;

        while (i > 1)
		{
                local i2 = i/2;
                local qi2 = q[i2];
                if (qi2$val <= kval)
			break;
                q[i] = qi2;
                i = i2;
		}

        q[i]=k;

	}

function pqremove(q:table[count] of retrec): retrec
	{
	# This function assumes that the length of the table
	#  is > 0
        local n = |q|;

        local i = 1;
        local d = q[1];
        local tmp = q[n];

        delete q[n];

        --n;

        if (n > 0)
		{
                local t1 = n/2;

                while (i <= t1)
			{
                        local j = 2*i;
                        local j1 = j+1;
                        if (j < n && q[j]$val > q[j1]$val)
                                j = j1;

                        local qj = q[j];
                        if (qj$val >= tmp$val)
				break;

                        q[i] = qj;
                        i = j;
			}
                q[i] = tmp;
		}
        return d;
	}

function MG_TopK(result: ResultVal, topk: count): vector of retrec
	{
	local retval: vector of retrec;
	local sort_buckets: table[count] of retrec;
	local median = result$mg_median;
	local offset = result$mg_offset;
	local val: double;

	for (key in result$mg_tbl)
		{
		val = result$mg_tbl[key];

		val += offset;		# Final result includes offset
		# If < topk elements in sort_buckets, just add
		if (|sort_buckets| < topk)
			pqinsert(sort_buckets, [$key=key, $val=val]);
		# If same as smallest bucket, we keep both of them
		#  (for now)
		else if (val == sort_buckets[1]$val)
			pqinsert(sort_buckets, [$key=key, $val=val]);
		# Otherwise put our val in if > root, and prune
		else if (val > sort_buckets[1]$val)
			{
			# This is a trifle inefficient - ideally, we should
			#  replace the root with the new value & rebalance
			#  (TBD another time)
			pqremove(sort_buckets);
			pqinsert(sort_buckets, [$key=key, $val=val]);
			}
		}

	# Now those that haven't had median applied
	for (key in result$mg_tbl_pre_median)
		{
		val = result$mg_tbl_pre_median[key] - median;

		if (val > 0.0)
			{

			val += offset;		# Final result includes offset
			# If < topk elements in sort_buckets, just add
			if (|sort_buckets| < topk)
				pqinsert(sort_buckets, [$key=key, $val=val]);
			# If same as smallest bucket, we keep both of them
			#  (for now)
			else if (val == sort_buckets[1]$val)
				pqinsert(sort_buckets, [$key=key, $val=val]);
			# Otherwise put our val in if > root, and prune
			else if (val > sort_buckets[1]$val)
				{
				pqremove(sort_buckets);
				pqinsert(sort_buckets, [$key=key, $val=val]);
				}
			}
		}

	# If filled up with more than topk entries due to duplicate values, delete excess
	while (|sort_buckets| > topk)
		pqremove(sort_buckets);

	# Fill up retval from minheap, back to front
	while (|sort_buckets| > 0)
		{
		local t = |sort_buckets| - 1;	# to avoid potential order of eval issues
		retval[t] = pqremove(sort_buckets);
		}

	return retval;
	}

