
## How to run
Examples as in the instruction:

fw = Firewall("fw.csv")</br>
print(fw.accept_packet("inbound","tcp",80,"192.168.1.2"))</br>
print(fw.accept_packet("inbound","udp",53,"192.168.2.1"))</br>
print(fw.accept_packet("outbound","tcp",10234,"192.168.10.11"))</br>
print(fw.accept_packet("inbound","tcp",81,"192.168.1.2"))</br>
print(fw.accept_packet("inbound","udp",24,"52.12.48.92"))

## Basic principles
1. Firstly the constructor read a given csv file line by line (in the form of batches). For each line, it parses the direction, 
protocol, port range and decimal convered ip address range, and stores in one of the four hash tables, which are four combinations of 
direction 
and protocol.</br>
2. For each hash table, the key is the discreted port number and the value is a list including all allowed ip ranges:</br>
[(ip1_start, ip1_end), (ip2_start, ip2_end), ...]</br>
This is an ascending sorted list based on the ip_start, and the ranges are not overlapped or adjacent.</br>
If the ip in the input is not a range, it is still coverted into a range with same ip_start and ip_end.</br>
3. For each incoming rule, find the direction, protocol, and port based on hash table and key, then insert the ip range into the sorted 
list. Merge all possible overlapping ip ranges and maintain the order of the list.</br>
4. After initialization, for each input, it finds the target list the same way as above and check whetherf the input ip is in a range.

## Function explanation
### __insert_ip(self, dict, port_start, port_end, ip_start, ip_end):</br>
For each ports in [port_start, port_end], insert an ip range (ip_start, ip_end) into the corresponding list and merge overlapping 
ranges, maintaining the order of the list
### __find_position(self, list, pos):</br>
Given a list of ordered non-overlapping tuples, find the position in the list such that:</br>
if the target position is within an existing range, and return the index of the range</br>
if the target position is not within an existing range, and return the index it should be when inserted. e.g.:</br>
list = [(1,3),(5,8)], pos = 0  ->  0, False</br>
list = [(1,3),(5,8)], pos = 9  ->  2, False</br>
list = [(1,3),(5,8)], pos = 4  ->  1, False</br>
list = [(1,3),(5,8)], pos = 2  ->  0, True</br>

### __merge_range(self, list):</br>
Merge possible overlapping and adjacent ranges in a sorted range list.</br>
e.g. [(1,2),(2,3),(6,8),(7,9)] - > [(1,3),(6,9)]

### Improvements
Since only 90 mintues is given, a more complex data structure could not be implemented within the time limit. The drawback of the 
current algorithm is during the initialization, if the port range is large then it has to iterate each port to fill every corresponding 
list.</br>
A more efficient implementation is to use a two-dimensional R-tree for each direction+protocol combination, where x-axis and y-axis 
represents ports and ip respectively. Each leaf contains at most one rectangle where the two sides represent the port range and ip 
range as in the coordinate, the rectangles do not overlap.</br>
When construct the tree, if the incoming rectangle is completely included in an existing rectangle within a leaf, nothing needs to do. 
If the incoming rectangle overlaps an existing rectangle, split this leaf containing the two overlapping rectangles into at most four 
leaves based on the sides of the rectangles, each of which contains at most one rectangle. Whenever the rectangles belong to each leaf 
of the same parent can combine into a large rectangle, merge them to form a new leaf to reduce the tree depth. The construction takes 
O(logn) time where n is the number of rules.</br>
When execute accept_packet, the search for the target point in the tree follows the same logic and takes O(logn) time, where n is the 
number of nodes in the tree.
