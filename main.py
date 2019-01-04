class Firewall(object):
    def __init__(self, file_name):

        file = open(file_name, 'r')

        # key: port, value: list of ip range tuples [(ip_start, ip_end), ...]
        self.inbound_tcp = {}
        self.inbound_udp = {}
        self.outbound_tcp = {}
        self.outbound_udp = {}

        while 1:
            lines = file.readlines(10000)
            if not lines:
                break

            for line in lines:

                direction, protocol, port, ip = line.strip().split(',')

                # convert port to a range [start, end]
                if '-' in port:
                    port_start = int(port.split('-')[0].strip())
                    port_end = int(port.split('-')[1].strip())
                else:  # if port is not a range, then port range is [port, port]
                    port_start = int(port.strip())
                    port_end = port_start

                # convert ipv4 address to a range [start, end]
                if '-' in ip:
                    ipv4_start = list(map(int, ip.split('-')[0].strip().split('.')))
                    ip_start = ipv4_start[0] * (256 ** 3) + ipv4_start[1] * (256 ** 2) + ipv4_start[2] * 256 + ipv4_start[3]
                    ipv4_end = list(map(int, ip.split('-')[1].strip().split('.')))
                    ip_end = ipv4_end[0] * (256 ** 3) + ipv4_end[1] * (256 ** 2) + ipv4_end[2] * 256 + ipv4_end[3]
                else:  # if ip is not a range, then ip range is [ip, ip]
                    ipv4_start = list(map(int, ip.strip().split('.')))
                    ip_start = ipv4_start[0] * (256 ** 3) + ipv4_start[1] * (256 ** 2) + ipv4_start[2] * 256 + ipv4_start[3]
                    ip_end = ip_start

                # update dictionary
                if direction == 'inbound' and protocol == 'tcp':
                    self.__insert_ip(self.inbound_tcp, port_start, port_end, ip_start, ip_end)
                if direction == 'inbound' and protocol == 'udp':
                    self.__insert_ip(self.inbound_udp, port_start, port_end, ip_start, ip_end)
                if direction == 'outbound' and protocol == 'tcp':
                    self.__insert_ip(self.outbound_tcp, port_start, port_end, ip_start, ip_end)
                if direction == 'outbound' and protocol == 'udp':
                    self.__insert_ip(self.outbound_udp, port_start, port_end, ip_start, ip_end)

        file.close()


    # for each port, insert (ip_start, ip_end) and merge overlapping ranges
    def __insert_ip(self, dict, port_start, port_end, ip_start, ip_end):
        for i in range(port_start, port_end + 1):
            if not i in dict:
                dict[i] = [(ip_start, ip_end)]
            else:
                insert_start, existed_start = self.__find_position(dict[i], ip_start)
                insert_end, existed_end = self.__find_position(dict[i], ip_end)
                if not (existed_start and existed_end and insert_start == insert_end): # if the range is not within another range
                    if existed_start:
                        dict[i].insert(insert_start + 1, (ip_start, ip_end))
                    else:
                        dict[i].insert(insert_start, (ip_start, ip_end))
                    dict[i] = self.__merge_range(dict[i])


    # find the position in a list of ordered non-overlapping tuples (i.e. ranges)
    # return the index of a range if the target position is within a existing range, with True
    # otherwise return the index it should be when inserted, with False
    # e.g. list = [(1,3),(5,8)], pos = 0  ->  0, False
    # e.g. list = [(1,3),(5,8)], pos = 9  ->  2, False
    # e.g. list = [(1,3),(5,8)], pos = 4  ->  1, False
    # e.g. list = [(1,3),(5,8)], pos = 2  ->  0, True
    def __find_position(self, list, pos):
        if not list:
            return 0, False
        if pos < list[0][0]:
            return 0, False
        if pos > list[-1][1]:
            return len(list), False

        left = 0
        right = len(list) - 1
        while left <= right:
            mid = int((left + right) / 2)
            if list[mid][0] <= pos and list[mid][1] >= pos:
                return mid, True
            if list[mid][0] > pos:
                right = mid - 1
            elif list[mid][1] < pos:
                left = mid + 1
        return left, False


    # merge possible overlapping and adjacent ranges in a sorted range list (sort by the first element of a tuple)
    # e.g. [(1,2),(2,3),(6,8),(7,9)] - > [(1,3),(6,9)]
    def __merge_range(self, list):
        res = []
        i = 0
        while i < len(list):
            end = list[i][1]
            j = i + 1
            while j < len(list) and list[j][0] - end <= 1:
                end = max(end, list[j][1])
                j += 1
            res.append((list[i][0], end))
            i = j
        return res


    def accept_packet(self, direction, protocol, port, ip):
        if direction != 'inbound' and direction != 'outbound':
            print("Invalid Direction")
            return False
        if protocol != 'tcp' and protocol != 'udp':
            print("Invalid Protocol")
            return False
        if port < 0 or port > 65535:
            print("Invalid Port")
            return False
        ipv4 = list(map(int, ip.strip().split('.')))
        if len(ipv4) != 4:
            print("Invalid IP")
            return False
        if ipv4[0] < 0 or ipv4[0] > 255 or ipv4[1] < 0 or ipv4[1] > 255 or ipv4[2] < 0 or ipv4[2] > 255 or ipv4[3] < 0 or ipv4[3] > 255:
            print("Invalid IP")
            return False

        ip_num = ipv4[0] * (256 ** 3) + ipv4[1] * (256 ** 2) + ipv4[2] * 256 + ipv4[3]
        if direction == 'inbound' and protocol == 'tcp':
            if not port in self.inbound_tcp:
                return False
            pos, valid = self.__find_position(self.inbound_tcp[int(port)], ip_num)
        if direction == 'inbound' and protocol == 'udp':
            if not port in self.inbound_udp:
                return False
            pos, valid = self.__find_position(self.inbound_udp[int(port)], ip_num)
        if direction == 'outbound' and protocol == 'tcp':
            if not port in self.outbound_tcp:
                return False
            pos, valid = self.__find_position(self.outbound_tcp[int(port)], ip_num)
        if direction == 'outbound' and protocol == 'udp':
            if not port in self.outbound_udp:
                return False
            pos, valid = self.__find_position(self.outbound_udp[int(port)], ip_num)
        return valid
