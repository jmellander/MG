This implements a variant of what is commonly known as the "Misra-Gries algorithm".
 Variants of it were discovered and rediscovered and redesigned several times over the years:

  "Finding repeated elements", Misra, Gries, 1982
  
  "Frequency estimation of Internet packet streams with limited space", Demaine, Lopez-Ortiz, Munro, 2002
  
  "A simple algorithm for finding frequent elements in streams and bags", Karp, Shenker, Papadimitriou, 2003
  
  "Efficient Computation of Frequent and Top-k Elements in Data Streams", Metwally, Agrawal, Abbadi, 2006

The current algorithm is based on:

  "A High-Performance Algorithm for Identifying Frequent Items in Data Streams",  Anderson, Bevin, Lang, Liberty, Rhodes, Thaler, 2017

Algorithms 4&5 of https://conferences.sigcomm.org/imc/2017/papers/imc17-final255.pdf
 See: https://github.com/DataSketches/sketches-core/blob/master/src/main/java/com/yahoo/sketches/frequencies/ItemsSketch.java
  for the authors' Java implementation
  ReversePurgeItemHashMap.java has the purge (DecrementCounters in the paper) implementation

See algorithm 4 in the paper for the basic concept.
 The UpdateCounters() algorithm as presented in the paper is a "stop the world" implementation, that
 is probably not the best choice for a realtime application like Bro.  So, this implementation uses
 a lazy delete algorithm.  Our lazy algorithm is as follows:

 First, we note that when UpdateCounters() is called, we actually only need to free up one slot,
  for the current item.
 So, we look for entries that haven't had the median applied updating the counters until we find a
  candidate for deletion and use that slot.  When another slot is needed, we continue thru the
  table of entries looking for the next candidate for deletion.  If we reach the end, we compute
  a new median, and start again at the beginning.  On average, we only expect to scan a few slots
  until we find one to be reused....  Simple, easy!  right?

 Well, a complication arises that table entries *after* where we are currently scanning may
  be updated in between freeing up slots, thus making the value different than would be under
  the original algorithm.  To avoid this, we use two tables, one has post-median values,
  and one with pre-median values.  We go thru the pre-median table, updating, and moving to
  the post median table if the value is > median.  If not, the entry is deleted, and the
  new entry is added to the post-median table (after application of the median).  When a
  new median is calculated, all the entries are moved to the pre-median table for the
  next round.  Each update, we amortize the cost by moving a few entries from pre to
  post median, as well as via a periodically scheduled event.

  At the end of the epoch, upon composing the final result, entries still marked with the
  prior generation will have the final median subtracted.

 A merge step occurs in a cluster context, where tables from multiple workers are merged by
  simply using the regular code above to update one table from the other, taking into account
  that some of the entries to be updated have not been modified in our lazy algorithm.
  For completeness, we can return the table in sorted order, or at least the TopK.


=== USAGE ===

Sumstats provides summary statistics (generally of network events) on a periodic basis.  MG allows for observations with a key and amount to be summed in a probabilistic manner that provides a reasonable estimate of heavy hitters of the observations.

Non-probabilistic SumStats obserations are made with a Key (either a host IP address, or a string) and an Observation (either a numeric value, or a string).  Each distinct Key creates a table on every worker that takes an Observation on that Key.

Probabilistic SumStats policies (HLL - HyperLogLog, TopK, and this one, MG) necessarily use an internal data structure to store their data, and a Key is not used, as this would obviate the memory advantages of using these policies.  HLL & TopK both take unit observations, and push their input to SumStats via the string Observation$str. MG uses Observation$str in place of the key & Observation$num to store the value.  Below are some examples for clarity:

Non-probabilistic SumStats:
SumStats::observe( "MySumStats", [$host=my_host], [$num=bytes] );

HLL or TopK probabilistic:
SumStats::observe( "MySumStats", [], [$str=fmt("%s",my_host)] );

MG probabilistic SumStats:
SumStats::observe( "MySumStats", [], [$str=fmt("%s",my_host), $num=bytes] );


The key difference between MG & the other probabilistic policies is that it allows an amount (typically a byte-count) to be observed along with a string (referred to as the key - although as noted previously, it doesn't use the Key field) that the amount refers to.  MG maintains a data structure that captures the sum of observation amounts by the key, and provides that data structure as the single result.  In line with other probabilistic policies, a function that efficiently provides a TopK of that data structure is provided, so that the Heavy Hitters can be identified.

There are several tunables that can be set when using MG is initialized:

mg_tbl_sz: Size of the Misra-Gries table, default 8192
MG_L: Number of entries to use for median calculation in algorithm, default 4*log2(mg_tbl_sz)

There are several demonstation policies included:

heavy_hitters.bro - uses regular SumStats SUM mechanism to track and report heavy hitters by IP.  In a production environment, this will likely cause an memory explosion.
mg-heavy_hitters.bro - uses MG mechanism for same purpose, with much less memory usage.

These policies use an undocumented feature of Sumstats to modify the sampling epoch to match the logging interval, so that it matches the default logging of other policies.  This is accomplished by storing the Sumstat in a global variable, rather than the usual practice of using an anonymous argument, which allows changing the epoch timeout during the epoch_finished function.

=== INSTALLATION ===

Either put in local.bro by

@load ./mg

or can be added to the Sumstats framework by:

edit share/bro/base/frameworks/sumstats/plugins/__load__.bro
and add the line

@load ./mg

then put mg.bro into the directory share/bro/base/frameworks/sumstats/plugins


