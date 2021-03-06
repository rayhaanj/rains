# Topologies

An assertion in RAINS must contain at least one signature to be valid. This
paradigm allows a user to check the validity of an assertion without having to
go through a recursive lookup (but he still needs all delegation assertions up
to the root). It is not only beneficial for a user but also for any entity using
or being part of the naming system. In this section, we are introducing several
topologies and strategies on how RAINS can be operated. We also list some
desirable properties and what the tradeoffs are between them. In the end, we
place each topology/strategy in the tradeoff space and analyse the advantages
and disadvantages of each approach.

## Tradeoff space

To evaluate different topologies we first have to determine in which properties
a client, developer or operator is interested in. Secondly, we point out which
of these properties influence each other to figure out where the tradeoffs are
lying. Finally, we evaluate where to place the different topologies in this
tradeoff space. Depending on the operational requirements an operator can then
choose which topology to deploy (or a mixture thereof).

### Query Latency

Query latency determines the amount of time a client has to wait for an answer
to his query. The smaller the value the faster a client can start a connection
with the destination. The value can be expressed as mean, average or tail
latency.

### Scalability

Scalability gives an indication about how many clients or queries the system
deployed in a certain topology can support before it starts to drastically slow
down. This property can also express how graceful overload is handled i.e. how
clients experience an overload situation.  

### Assertion publishing complexity

A zone authority makes information about its zone accessible through its
authoritative servers. Depending on the topology and the method used there might
be different amount of steps involved in publishing the zone's information. E.g.
the number, location and task of the authoritative servers.

### Availability/Security (Client side)

A client expects the system to be highly available and to obtain correct
information from it. The harder it is to break the delegation chain or to
prevent the client to obtain an answer for his query the better the topology
performs in this metric.

### Robustness (authoritative side)

The difficulty for an attacker to prevent a zone authority to publish
information about its zone to the system determines the robustness of the
topology.

### Privacy

Depending on the topology the difficulty for an attacker to obtain private
information varies. This property measures how much effort a given attacker
model has to invest to gain a certain amount of information about a client.

### Troubleshooting complexity

Troubleshooting complexity measures the difficulty for an operator to determine,
locate and fix an error scenario.

### Cost

Cost states an estimate of the monetary cost each of the topologies has. It can
include how the costs are divided between the operators of the system and the
source of the cost such as electricity, location, number of operators etc. 

### Maintainability

Maintainability describes the effort operators have to invest to keep the system
running i.e. to update malfunctioning or old hardware, update the amount of
servers depending on the amount of queries, etc.

## Tradeoffs

In general, there is a tradeoff between serving each client from a close by
local server or from a larger, high performance and further away server. The
first approach requires the servers to be locally distributed at many different
places close to the clients where as in the second suggestion there are fewer
locations with more servers to which a larger group of clients send their
queries. The advantage of local servers are lower latency due to the shorter
network path and possibly many cache hits as clients from the same region speak
the same language and will visit similar websites (based on similar interests,
events, news, etc.). But once a client accesses a lesser known website it is
with high probability not in the cache. The more centralized servers have larger
caches and a much broader range of clients and thus, the probability of having a
cache hit will probably be higher. Next, we are listing the tradeoffs between
the above properties and why they occur.

- Cost vs Latency: Deploying additional/less servers closer to the clients.
- Cost vs Scalability: Deploy more/less servers
- Cost vs Availability: Having more/less redundant servers
- Cost vs Robustness: Having more/less authoritative servers and bandwidth
- Cost vs Privacy: Depending on the approach more servers are needed
- Cost vs Troubleshooting: Bad tools -> more work -> more operators
- Cost vs maintainability: Bad maintainability -> more operators
- Latency vs Security: More/less security checks influence latency
- Latency vs Robustness: less robust -> more failures -> partly higher latency
- Latency vs Privacy: Depending on the method, much higher latency (e.g. mixnet)
- Scalability vs Assertion publishing complexity: obvious
- Scalability vs Security: More defenses -> more machines&complexity -> less scalable 
- Scalability vs troubleshooting complexity -> obvious
- Scalability vs Maintainability: The larger the system the harder to maintain
- Assertion publishing complexity vs availability: more complex -> more things
  can go wrong -> reduced availability
- Assertion publishing complexity vs maintainability: obvious
- Availability vs privacy: no privacy -> no availability
- Availability vs Troubleshooting complexity: fix takes longer -> more downtime
- Robustness vs Privacy: more features -> more possible issues -> less robustness
- Robustness vs maintainability: more server/complex behavior -> less maintainable
- Privacy vs Troubleshooting complexity: more private -> harder to troubleshoot

## Centralized

### Setting

The centralized topology can be divided into two actors. The naming authorities
and the centralized resolver. The naming authorities provide the information to
the centralized resolver and all clients are sending their queries to the
centralized resolver. The centralized resolver is located at one location and
all traffic is going through it. To remedy a total outage the resolver can be
replicated at a different location which only takes over when the primary
resolver fails. The centralized resolver has a global view of the naming
ecosystem and performs consistency checks and validates the information it
receives. Several strategies can be used for the communication between the
naming authorities and the centralized resolver such as:

- Push only (by naming authority)
- Cache miss only (by centralized resolver)
- Fetch n most queried names before expiration, else only on cache miss

### Use case

- Small to mid size companies with few close locations

### Discussion

A centralized resolver is not only a single point of failure but also a single
instance all clients using the naming system must agree on. All queries are
going through it which reduces its scalability. The latency corresponds to the
distance of the client to the resolver as long as the resolver can handle the
load. In a company setting where the queries are only coming from withing the
company, the amount of clients and queries are predictable and the necessary
hardware and cache size for the resolver can be estimated. Maintainability is
easy as everything is at a single location. As all the queries go through this
one resolver, the company can easily put policies in place which sites are
allowed to be accessed (by knowing the IP beforehand or changing the default
resolver a knowledgeable user can go around this access control). As the load is
predictable and the system is at a single location, monetary cost will be low.
The push only strategy only works when the company has a relationship with the
naming authority. The Cache miss only strategy is the simplest one but every
time an assertion expires, on the next request a recursive lookup has to be
performed which increases latency. Fetching updated assertions of the n most
queried names before they expire is a possible optimization heuristic to reduce
latency.

## Centralized controller with distributed caching resolvers

### Setting

This approach is similar to the centralized topology with the difference that
the centralized resolver is divided into two parts, one centralized controller
and many distributed caching resolvers. The centralized controller performs the
task of the centralized resolver in the previous topology. The distributed
caching resolvers reduce latency substantially for common query patterns. In
case of a cache miss, the caching resolver forwards the query to the centralized
controller which on a cache hit responds directly or else does a recursive
lookup.

### Use case

- Large size companies
- Companies with several locations that are geographically far apart

### Discussion

The same holds true as for the centralized topology. With the small difference
that maintainability is getting a bit harder as the servers are geographically
distributed and cost will be slightly higher. As the caching resolvers are not
performing recursive lookup themselves but go through the centralized
controller, latency is a bit higher. But with this approach the centralized
instance keeps control over the naming system and can still enforce its policy.
control. Depending on the query pattern it might even reduce latency for other
caching resolvers in case the centralized controller still has a cached answer.

## Many independent closed recursive resolvers

RAINS can be operated the same way DNS is currently operated [1]. That means
there are caching and recursive name servers.  A client sends a query to the
caching server of its ISP. If there is a cache hit, the response is directly
sent back to the querier. Otherwise, a recursive lookup is performed by the ISP.

### Setting

A client purchases access to a local closed recursive resolvers. In today's
setting this would be the client's ISP. The resolver caches previous results to
improve latency and performs recursive lookup on a cache miss for its customers.
Similar to DNS, there must be a public root zone where each of the independent
recursive resolvers can start their recursive lookups. This root zone is managed
in the Internet by IANA [10] and the root servers are operated by several
entities. In SCION, the root zone will be managed and servers provided by the
ISD core and affiliated entities. The root servers store delegations and
redirection entries to authoritative servers of all top-level domain.
Authoritative servers serve information about the namespace they have authority
over to any legitimate querier. In case there are multiple root zones, as we
envision for SCION, there also needs to be a naming consistency observer (NCO).
The NCO sends queries to all zones and checks if the response is coherent with
the zone's published public policy. This ensures that all naming inconsistencies
are public and transparent.

### Use case

- Internet
- SCION

### Discussion

This topology scales to the size of the Internet. This is due to the namespace
being hierarchical and the many independent entities where each of them operate
a small part of the system. They either provide recursive lookup or host
authoritative servers for their namespace. For an average client latency will be
low as long as she chooses a resolver close by. Publishing information about a
zone is quit easy for the authority as it can push the newly signed assertions
to its own, local authoritative servers to which a redirection assertion points
stored in the superordinate zone. An authority must be able to defend DDoS
attacks against its authoritative servers if it does not want itself and all of
its subzones to become unavailable. A recursive resolver learns the whole
browsing history of a client as long as it uses only one resolver. This is not
desirable for a client putting emphasis on her privacy. The cost of operating
the naming system is split up among many entities which makes it affordable. The
fact that each entity has its information stored on local machines makes each
part of the system easy to maintain. But it also makes it hard to troubleshoot a
non local failure due to the many independent, distributed entities involved.

Advantages:

- Large scale deployment experiences from DNS

Disadvantages:

- If an entry is not in the cache, recursive lookup takes a long time
- New RAINS features are not used and RAINS' TCP connection is slower than DNS'
  UDP
- An attacker might be able to link a new connection with a recursive lookup and
  thus, finds out about the querie's content even though the connection between
  client and caching server is over TCP

## Few independent high-performance open recursive resolvers

In recent years, large tech companies started deploying open recursive DNS
resolvers such as Google's and Cloudflare's public DNS [2,3], or IBM's Quad9
[3]. These companies hope that users are going to use their DNS resolver instead
of the user's ISP's one. They argue that they value the user's privacy more and
are more secure by not resolving names they suspect being malicious. Due to
their size they are able to gather better information about malicious domains
and thus, are more accurate than most ISPs.

### Setting

In this topology, there are several clusters each consisting of many
high-performance DNS resolvers which potentially share one cache. These clusters
are distributed around the world to reduce latency. Few large entities operate
these clusters. This service is either provided for free or some kind of fee
must be paid. A client can decide to which set of these large open resolvers it
wants to send its queries. In case the open resolver does not have a cache hit,
it performs a recursive lookup. The setting for name authorities and the root
zone manager are the same as in the previous topology.

### Use case

- Internet
- SCION

### Discussion

TODO CFE look at other properties described before

Advantages:

- Scalable?
- Very fast [6]. As lots of people are using this resolver the probability that
  your query's answer is cached is high. The client is still connecting to a
  local instance which likely contains local names.
- Large scale deployment experiences from some large tech companies
- You trust one large tech company to value your privacy
- Higher security
- Facilitates initial deployment besides DNS (in case the client's ISP does not
  yet support RAINS.)

Disadvantages:

- In straight forward copying this approach the new RAINS features are not used
  and RAINS' TCP connection is slower than DNS' UDP.
- The operator of this large resolver learns all requests of all its users. A
  user just has to trust the operator to not misusing her data.

## Current State: Deployment of both above topologies

### Setting

See above

### Use case

- Internet

### Discussion

By having both of these topologies, a client has more choices to select from to
satisfy her requirements. Using the same topologies for RAINS would also work
out but does not give it a special advantage over the current system (except
being more secure and allowing for more optimizations).

## P2P of authoritative servers with distributed independent caching resolvers

### Setting
Instead of having authoritative server(s) for each zone, the assertions are
stored in a peer to peer fashion where each zone authority and each independent
caching resolver is a peer. Clients are not part of the P2P system and can only
send queries to one of the caching resolvers which fetch the queried information
from the corresponding node in the P2P system. We could use Chord [9], a
scalable peer-to-peer looup service for Internet Applications, to store the
naming information. Instead of doing a recursive name lookup, the lookup is done
in Chord. Because the keys are distributed evenly among the nodes of the system,
the larger a Registree (or registrar?) is, the more nodes it must have. The
approximate number of keys per node can be determined by IANA (ICANN) to
regulate how much load a node must expect. As a key in Chord we use the fully
qualified domain name.

### Use case

- Internet

### Discussion

The main difference of this topology compared to the current state is the lookup
process in case of a cache miss and where the data is stored. Lookup latency in
chord is logarithmic in the number of nodes where as in a recursive lookup it
depends on the depths of the name in the hierarchy. The lower a name is in the
hierarchy the better chord performs compared to recursive lookup. But in current
DNS most of the names are close to the root and thus, a recursive lookup would
be faster. The amount of time for a lookup in chord is much more unpredictable
than one in a recursive setup which is more or less constant as the geographical
location of the data is static whereas in chord it changes for some names when a
new node joins. There are some suggestions in the paper to decrease latency by
changing the content and working of the finger table. Mainly by trading space
for latency. If this system scales up to the needs of a global naming system
remains to be seen. The assertion publishing complexity is certainly higher as
the naming authority first has to find out where to push each entry and then
send it. It also has to notice when a node containing some of its information
leaves the system and resend these assertions to the successor node. On the one
hand, it is much harder for an attacker to take down an entire zone because its
naming information is approximately, uniformly distributed among all nodes. But
on the other hand, if an attacker targets a specific domain which happens to be
stored at a weaker node, the naming authority over this name can do nothing to
prevent the attack as the other node is not under its control (which would allow
it to increase the number of servers etc.). There must be some kind of
punishment for a node operator in case it cannot serve its assigned names for
more than a defined amount of time. This system is also less robust and
predictable from an operator perspective as the system is much more dynamic.
E.g. a node might get many more names it must serve in a short amount of time in
case one or multiple consecutive predecessors leave. In terms of a client's
privacy nothing changes as her connection point is still the same, a caching
resolver. For an naming authority it is much harder to troubleshoot problems as
the system is more dynamic and more steps are involved from where to store the
different assertions to how to find the correct location, etc. Thus, also the
cost will increase for a naming authority as its mode of operation is more
complex and it has to be prepared for locally large changes in a short amount of
time. But because also every caching resolver is a node of the system, the
amount of names a naming authority is serving is smaller than before which
reduces infrastructure cost for it. From a maintainability side, it will be
similar to current topologies, as naming authorities still have their servers
locally or externally managed in the cloud.

### Issue

- Maybe some mechanism is needed to store a key at multiple nodes to prevent an
  attacker to easily DDoS an important domain in case it happens to end up at a
  weak node.
- Could we change chord to assign certain nodes more names than others without
  having assigning several nodes to the same entity which increases lookup path
  length.

## P2P on a client level, naming authority push & act as backup?

### Setting

Every client is part of the naming system. Based on a function, an assertion is
stored at several clients. The replication extent is based on the estimated
number of queries this name get in a defined time interval. An ISP must not only
provide a router to each of its clients but also a small device which acts as a
RAINS server. Authoritative servers push assertions to the corresponding clients
based on the function. The function should replicate a name close to places
where it is often queried.

### Use case

- Internet

### Discussion

### Issue

- Who calculates this function
- Can such a function even exist
- How to estimate the number of queries a name gets
- How to figure out where replicate a name without losing too much privacy
- Authorities do not have control over the servers who serve their names
- In bad circumstances a name might 'disappear' e.g. when clients who serve it
  stop using their name server.
- How to find out where to send your queries to
- How to find best location to send query to

## Peer to peer network TODO CFE

Instead of having large entities which operate high performance rains servers
all over the world, an entry could be distributed among several rains servers of
different authorities (optimally in different parts of the world to reduce
latency). Similar to PNRP [8] or chord [9].This approach distributes the load
over many different servers providing the naming service. The popularity of a
domain determines how much it is distributed (otherwise, the server responsible
for google.com would certainly break down). Each AS (ISP) would be one peer.
Based on the used hash function it is clear for each client where to find an
entry. Based on the highly dynamic behavior of the system the entries might
change too often. It is also doubtable that such a system scales to the
requirements of a global naming system. Based on the knowledge from where an
entry is served, it becomes easier for an attacker to target certain domains and
just DDoS those servers which are responsible for the targeted domain. It is
especially critic for small domains as they are served only from few servers.

## Bibliography

[1] How DNS works (26.06.18)
https://www.appliedtrust.com/resources/infrastructure/understanding-dns-essential-knowledge-for-all-it-professionals  
[2]Google public DNS (26.06.18) https://developers.google.com/speed/public-dns/  
[3] Quad9 IBM's public DNS (26.06.18) https://www.quad9.net/  
[4] Cloudflare's public DNS (26.06.18) https://1.1.1.1/  
[5] Blog about 1.1.1.1 (26.06.18) https://blog.cloudflare.com/announcing-1111/  
[6] dnsperf (26.06.18) https://www.dnsperf.com/#!dns-resolvers  
[8] PNRP (30.06.18)https://en.wikipedia.org/wiki/Peer_Name_Resolution_Protocol  
[9] Chord (30.06.18) http://nms.csail.mit.edu/papers/chord.pdf  
[10] Root Zone Management https://www.iana.org/domains/root  
[11] Root server operators https://www.iana.org/domains/root/servers  