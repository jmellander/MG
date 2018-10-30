#
# $Id: mg-heavy_hitters.bro,v 1.1 2018/10/30 17:49:05 melland Exp melland $
#
# Heavy Hitters

module MGHeavyHitters;

export {
	# Create an ID for our new stream. By convention, this is
	# called "LOG".
	redef enum Log::ID += { LOG };

	# Define the record type that will contain the data to log.
	type Info: record {
		start_time: time	&log;
		end_time: time		&log;
		#group: string		&log;
		bytes_out: count	&log;
		info: string		&log;	# Description
	};
}

const MIN_SAMPLE = 1 &redef;		# Don't record samples less than this

global MGHeavyHitters::recurring_connection_observe: event(id: conn_id);

global epoch_in_progress: bool;
global epoch_start: time;
global epoch_start_real_time: time;
global epoch_wall_time: interval;
global epoch_result_count: count;

type conn_rec: record {
	orig_bytes_out: count &default = 0;
	resp_bytes_out: count &default = 0;
};

global conns: table[conn_id] of conn_rec;	# Table of connections seen during this sampling period

type host_tbl: table[string] of count &default = 0;	# Host table prototype

# Used for sorting
type host_rec: record {
	ip: string;
	byte_count: count;
};

type interval_rec: record
	{
	time_interval: interval;		# interval that this record corresponds to
	hosts: host_tbl;			# Values for hosts of this interval
	grand_total: count;			#  Grand total of hosts
	start_time: time;			# Starting time of this interval
	end_time: time;				# Ending time of this interval
	sort_buckets: table[count]		# Sort buckets, based on log10 of interval_rec$hosts
		of set[string];

	# filter_function is used to filter out IPs that are not part of the set to be totaled
	#  Default: total all IPs
	filter_function: function(ip: string): bool
		&default = function(ip: string): bool {return T;};

	# report_function is the function to use for the report heading
	#  Default: as seen below
	report_function: function(start: time, end: time, val: string): string
		&default = function(start: time, end: time, val: string): string
			{
			local retval = val;
			local timefmt = "%y-%m-%d_%H.%M.%S";
			if (val == "Grand Total")
				retval = fmt("Grand Total MG-Heavy Hitters report from %s to %s",
					strftime(timefmt, start), strftime(timefmt, end));
			return retval;
			};

	# grouping_function allows grouping by e.g. subnet or ASN
	#  Default: string representation of IP
	grouping_function: function(ip: string): string
		&default = function(ip: string): string {return ip;};
		# FIXME below for string representation of ip
		# ASN lookup below: if lookup_asn() still worked :-(
		#&default = function(ip: addr): string {return fmt("%d",lookup_asn(ip));};
		# Country code lookup below
		#&default = function(ip: addr): string {local t=lookup_location(ip); return t?$country_code ? t$country_code : "??";};
		# Subnet code lookup below
		#&default = function(ip: addr): string {return fmt("%s", mask_addr(ip, 16));};
	};

global intervals: vector of interval_rec;

global sampling_interval: interval;		# The interval to be used by sumstats
global next_sample: time;			#  Next time the sample will be taken

function reset_interval_rec(a: interval_rec)
	{
	a$hosts = table();
	a$grand_total = 0;
	a$sort_buckets = table();
	}

function new_interval_rec(): interval_rec
	{
	local a: interval_rec;
	reset_interval_rec(a);
	return a;
	}

event MGHeavyHitters::FirstTime() &priority = 10
	{
	# FIXME: Initialize intervals vector (could be done above, but...)

	intervals[0] = new_interval_rec();
	intervals[0]$time_interval = 10 min;

	intervals[1] = new_interval_rec();
	intervals[1]$time_interval = 1 hr;
	
	intervals[2] = new_interval_rec();
	intervals[2]$time_interval = 2 hr;

	# Put additional intervals here - this will be the order in
	#  which they are reported

	# Interval for sampling - the shortest of the above
	#  To avoid problems, all intervals should be multiples of
	#  sampling_interval.
	sampling_interval = intervals[0]$time_interval;
	
	for (i in intervals)
		{
		if (intervals[i]$time_interval < sampling_interval)
			sampling_interval = intervals[i]$time_interval;
		intervals[i]$start_time = network_time();
		intervals[i]$end_time = network_time() + calc_next_rotate(intervals[i]$time_interval);
		}

	# First sample will most likely be short, as we align to the log rotation interval
	next_sample = network_time() + calc_next_rotate(sampling_interval);

	#next_sample = network_time() + sampling_interval;
	}

# Debugging function
function print_id(id: conn_id): string
	{
	return fmt("%s:%s-%s:%s",id$orig_h, id$orig_p, id$resp_h, id$resp_p);
	}

# Some of the observation functions/events use conn_id, others use connection. connection_exists(conn_id) is F
#  during connection_state_remove(), so we need to use connection here instead of conn_id, although conn_id is more
#  convenient generally.

# Connection observation, calc difference from last measurement of this connection & add to sumstats,
function observe(c: connection)
	{
	local orig_bytes = c$orig$num_bytes_ip;
	local resp_bytes = c$resp$num_bytes_ip;

	# No point in going on if below threshold
	if (orig_bytes < MIN_SAMPLE && resp_bytes < MIN_SAMPLE)	return;	

	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local new_orig_bytes: count;
	local new_resp_bytes: count;

	if (id in conns)
		{
		# Add in the difference between the last measurement and this one
		new_orig_bytes = orig_bytes - conns[id]$orig_bytes_out;
		new_resp_bytes = resp_bytes - conns[id]$resp_bytes_out;
		}
	else
		{
		# This code branch will be taken upon the new_connection() event.
		# Also, some connections aren't captured until they end, so are not in conns.
		#  These appear to be connections instantiated by a broadcast request (Netbios, DHCP)
		#  that are responded to by a specific host, so they are captured here, too.

		new_orig_bytes = orig_bytes;
		new_resp_bytes = resp_bytes;

		# Add to conns
		local c1: conn_rec;
		conns[id] = c1;
		}

	# Update conns record
	conns[id]$orig_bytes_out = orig_bytes;
	conns[id]$resp_bytes_out = resp_bytes;

	# Add to Sumstats
        if (new_orig_bytes >= MIN_SAMPLE)
		{
		SumStats::observe( "MG-HeavyHitters", [], [$str=fmt("%s",orig), $num=new_orig_bytes] );
		}
        if (new_resp_bytes >= MIN_SAMPLE)
		{
	        SumStats::observe( "MG-HeavyHitters", [], [$str=fmt("%s",resp), $num=new_resp_bytes] );
		}
	}

function observation_schedule(id: conn_id)
	{
	if (connection_exists(id))
		{

		local now = network_time();

		# Schedule an observation just before the epoch
		local next_observation = next_sample - 15sec ;

		# Change to T to introduce a little randomness in the observation timing
		#  can't use += with time
		if (T)	next_observation = next_observation + double_to_interval(rand(10000000)/1000000.0) ;

		# In case we've already passed next_observation, schedule for next epoch
		while (next_observation < now)
			next_observation = next_observation + sampling_interval;

		# Cap the next observation time at 10 minutes, which ensures that we don't keep
		#  expired connections around for too long (until the end of the epoch)
		if (next_observation > now + 10 min)    next_observation = now + 10 min;

		schedule next_observation - now
			{ MGHeavyHitters::recurring_connection_observe(id) };
		}
	}

# Recurring connection observation event
event MGHeavyHitters::recurring_connection_observe(id: conn_id)
	{

	# If the connection has already ended, skip
	if (connection_exists(id))
		{
		observe(lookup_connection(id));

		# Next observation
		observation_schedule(id);
		}
	}

# Begin recurring observations upon new connection
event new_connection(c: connection)
	{
	# First observation
	observe(c);

	# Schedule recurring observations
	observation_schedule(c$id);
	}

# When connection ends, perform final observation
event connection_state_remove(c: connection)
	{
	observe(c);
	delete conns[c$id];
	}

function sort_step(ip: string, which: count)
	{
	# Here we add the ip to a bucket based on log10(data transferred). Since this is incremental, an ip
	#  could be in a small bucket at first, and proceed to a higher bucket.  The actual sort will
	#  only consider the highest bucket that an IP is in.
	# Note that the ip variable does not necessarily represent just one ip, grouping_function() is used to possibly
	#  total multiple ips by subnet, ASN, or any other criterion.
	# This could be done in a different way, using a heap, which possibly could be more efficient in
	#  a general case of evenly distributed values, but probably with network traffic a few flows
	#  will be dominant, which may make this more efficient (especially since logarithms are done in HW on all
	#  modern systems).
	#  There are also a few tricky considerations, not mentioned here, in using a heap for this application.

	# Why add 1, below? So that we don't need a special test for 0 (which shouldn't happen, but...)
	#  Why multiply by a constant?  Increases number of buckets...

	local bucket_num: count = double_to_count(20.0*log10(intervals[which]$hosts[ip] + 1.0));

	if (bucket_num !in intervals[which]$sort_buckets)
		intervals[which]$sort_buckets[bucket_num] = set();

	add intervals[which]$sort_buckets[bucket_num][ip];
	}

# Return the top Num_to_report hosts from ip_tbl
#  The incremental step was a bucket sort by order of magnitude.
#  Here we pull from the top buckets, until we have enough, then perform a standard sort.

function sort_ips(host_counts: host_tbl, buckets: table[count] of set[string], Num_to_report: count) : vector of string
	{

	local idx: count;
	local ip: string;
	local s: set[string];
	local sort_vec: vector of host_rec;		# IPs sorted by max bytes transferred
	local ret_vec: vector of string;
	local hi_bucket = 0;

	if (|host_counts| <= Num_to_report)
		{
		# If we have less IPs than we want to report, then just put them all in
		for (ip in host_counts)
			sort_vec[|sort_vec|] = [ $ip = ip, $byte_count = host_counts[ip] ];
		}
	else
		{
		for (idx in buckets)	if (idx > hi_bucket)	hi_bucket = idx;

		# Consolidate buckets until we have enough, counting down
		#  We use a set to ensure no duplicates - see sort_step()
		while ( T )
			{
			if (hi_bucket in buckets)
				{
				for (ip in buckets[hi_bucket])	if (ip !in s)
					{
					add s[ip];
					sort_vec[|sort_vec|] = [ $ip = ip, $byte_count = host_counts[ip] ];
					}	
				if (|s| >= Num_to_report)	break;
				}

			if (hi_bucket == 0)	break;
			--hi_bucket;
			}
		}

	# Sort buckets we're considering

	# Mitigation for 64-bit problem with sort()
	sort(sort_vec, function(ip1: host_rec, ip2: host_rec): int { if (ip2$byte_count > ip1$byte_count) return 1; if (ip2$byte_count < ip1$byte_count) return -1; return 0; });

	# Put into vector of addresses
	for (idx in sort_vec)	ret_vec[idx] = sort_vec[idx]$ip;

	# and size to correct amount
	if (|ret_vec| > Num_to_report)	resize(ret_vec, Num_to_report);

	return ret_vec;
	}

function do_report(which: count)
	{
	local output = sort_ips(intervals[which]$hosts, intervals[which]$sort_buckets, 20);
	local rec: MGHeavyHitters::Info;
	rec$start_time = intervals[which]$start_time;
	rec$end_time = intervals[which]$end_time;

	local running_total = 0;
	for (i in output)
		{
		rec$bytes_out = intervals[which]$hosts[output[i]];
		rec$info = intervals[which]$report_function(rec$start_time, rec$end_time, output[i]);
		Log::write(MGHeavyHitters::LOG, rec);

		running_total += intervals[which]$hosts[output[i]];
		}

	# Non reported IPs - this is Grand Total - running total
	rec$bytes_out = intervals[which]$grand_total - running_total;
	rec$info = intervals[which]$report_function(rec$start_time, rec$end_time, "Other");
	if (rec$bytes_out > 0)	Log::write(MGHeavyHitters::LOG, rec);

	# Grand total
	rec$bytes_out = intervals[which]$grand_total;
	rec$info = intervals[which]$report_function(rec$start_time, rec$end_time, "Grand Total");
	if (rec$bytes_out > 0)	Log::write(MGHeavyHitters::LOG, rec);
	}


global hh: SumStats::SumStat;	# Needs to be a global, so it can be modified in epoch_finished.

# This is called to get the ball rolling, on the first packet...
event MGHeavyHitters::FirstTime()
	{

	local red: SumStats::Reducer = [$stream="MG-HeavyHitters", $apply=set(SumStats::MG)];

	hh = [$name="MG-HeavyHitters", 
		$epoch=sampling_interval,
		$reducers=set(red),
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
			{
			# Called for each result - in this case, there is only one result
			#  Which returns a table of HeavyHitters
			local r = result["MG-HeavyHitters"];
			local ips = SumStats::MG_TopK(r, 20);
			for (res in ips)
				{
				local ip=ips[res]$key;
				local ip_str: string;
				local amt:count = double_to_count(ips[res]$val);
				local which: count;

				for (which in intervals)
					{
					# If this is an IP we want to track
					#  IPs can be excluded by returning F from filter_function
					#  so that, e.g. only remote or local addresses are considered.
					if (intervals[which]$filter_function(ip))
						{
						# Use grouping function to put IP address into a group
						#  By default, this is a string representation of the IP
						#   so that each IP is its own group, but can be used
						#   for grouping by subnet, ASN, Country Code, etc.
						ip_str = intervals[which]$grouping_function(ip);
						if (ip_str in intervals[which]$hosts)
							intervals[which]$hosts[ip_str] += amt;
						else
							intervals[which]$hosts[ip_str] = amt;

						sort_step(ip_str, which);	# Incremental sort step
						}
					}
				}

			# Not strictly correct, but no way around it...
			for (which in intervals)
				intervals[which]$grand_total += double_to_count(r$mg_grand_total);
			},
		$epoch_finished(ts: time) = 
			{
			local which: count;

			for (which in intervals)
				{
				# Here check trigger times for intervals, and report & reset if reached
				if (network_time() >= intervals[which]$end_time || bro_is_terminating())
					{
					do_report(which);

					# Reset stats for next time & update interval
					intervals[which]$start_time = intervals[which]$end_time;
					intervals[which]$end_time =
						intervals[which]$start_time + intervals[which]$time_interval;
					reset_interval_rec(intervals[which]);
					}
				}

			hh$epoch = calc_next_rotate(sampling_interval);
			next_sample = network_time() + hh$epoch;
			}
		] ;

	SumStats::create( hh );

	}

event bro_init() &priority=5
	{
	# Schedule the beginning of the sampling as soon as possible, after network_time()
	#  is available
	schedule 0usec { MGHeavyHitters::FirstTime() };

	# Create the logging stream. This adds a default filter automatically.
	Log::create_stream(MGHeavyHitters::LOG, [$columns=Info, $path="mgheavyhitters"]);

	# Randomize
	srand(double_to_count(time_to_double(current_time())));
	}

