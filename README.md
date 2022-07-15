# RusTCP (version 0.1)

[RusTCP](https://github.com/ccie18643/RusTCP) RusTCP is an attempt to rewrite some of the [PyTCP](https://github.com/ccie18643/PyTCP) stack functionality using Rust language. Currently, the main goal of this project is to create a stable IPv6 platform that could be used to facilitate the process of labing the SRv6 technology.

### Examples:


#### Stack initialization, IPv6 DAD successfuly assigning two addresses

![Sample RusTCP log output](https://github.com/ccie18643/RusTCP/blob/master/doc/images/ip6_dad_00.png)
![Sample RusTCP log output](https://github.com/ccie18643/RusTCP/blob/master/doc/images/ip6_dad_01.png)


#### Stack initialization, IPv6 DAD fails to assign 2007::7 address due to another host using it already

![Sample RusTCP log output](https://github.com/ccie18643/RusTCP/blob/master/doc/images/ip6_dad_02.png)
![Sample RusTCP log output](https://github.com/ccie18643/RusTCP/blob/master/doc/images/ip6_dad_03.png)


#### Sending response to ICMPv6 ND Neighbor Solicitation and replying to ping requests

![Sample RusTCP log output](https://github.com/ccie18643/RusTCP/blob/master/doc/images/ip6_ping_00.png)
![Sample RusTCP log output](https://github.com/ccie18643/RusTCP/blob/master/doc/images/ip6_ping_01.png)

#### Using Eui64 + ICMPv6 Router Solicitation / Router Advertisement mechanism to automatically assign LLA and GUA addresses

![Sample RusTCP log output](https://github.com/ccie18643/RusTCP/blob/master/doc/images/ip6_autoip_00.png)
![Sample RusTCP log output](https://github.com/ccie18643/RusTCP/blob/master/doc/images/ip6_autoip_01.png)
