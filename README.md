# Firewall
Used 4 maps to store the mapping of port and ip address of different direction and protocol.

Unit test first. Test each function. Test file reading. Then test the whole class, whether a good input can get a right result, whether a bad input can cause exception.

If the requirement of time complexity of accept() is more strict, I may merge the range of each ip address each time when the rule is added, so the map will only store the port and the range of ip address which doesn't overlap. Every time, I only need to search the nearest start of ip range which is smaller or equivalent to the input ip. In this condition, adding rules may cost more time, but accept() will cost less time.

I created a test file. It includes 4 valid rules. I tested each rules, and some invalid input.

My preference of teams is Platform, Data and Policy.
