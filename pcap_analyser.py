'''modules which are needed to analyse pcap'''
import json
import os
import shutil
from collections import Counter
import re
import socket
import datetime as dt
import dpkt
from prettytable import PrettyTable


def create_table(count, mean, fts, lts):
    '''Table to summarize packet'''
    pretty_table = PrettyTable()
    pretty_table.field_names = ['No of Packet',
                                'Mean Packet',
                                'First Timestamp',
                                'Last Timestamp']
    pretty_table.add_row([count, mean, fts, lts])
    print(pretty_table)


def open_pcap(o_p):
    '''Open pcap file '''
    # empty list for source ip
    src_ip_list = []
    # empty list for timestamp
    time_stamp_list = []
    # empty list for count (TCP,UDP,IGMP) packet
    count_tcp = []
    count_udp = []
    count_igmp = []
    # tcp,udp,igmp mean packet
    tcp_total, udp_total, igmp_total = 0, 0, 0
    # proto list
    ip_address = []
    # mean packet contains (tcp,udp,igmp)
    mean_packet = []
    with open(o_p, 'rb') as pf:
        pcap = dpkt.pcap.Reader(pf)
        for ts, buf in pcap:
            # contain dst,src....
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            proto = ip.data
            # change src into decimal code
            ips = socket.inet_ntoa(ip.src)
            # change des into decimal code
            ipdes = socket.inet_ntoa(ip.dst)
            # add into ip list
            src_ip_list.append((ips, ipdes))
            # 4. for ip src and des pairs for all packet
            ip_address.append(ip)
            # timestamp
            t_s = str(ts).split(".")[0]
            ts = dt.datetime.fromtimestamp(int(t_s))
            ts = ts.strftime("%Y-%m-%d")
            # add into timestamp empty list
            time_stamp_list.append(ts)
            # check tcp packet
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp_data = proto
                count_tcp.append(tcp_data)
                # sum TCP packet length
                tcp_total += len(tcp_data)
                # print (f'{repr(tcp_data)}')         #repr: chang byte to dec
            # check udp packet
            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                udp_data = proto
                # add into udp empty packet list
                count_udp.append(udp_data)
                # sum UDP packet length
                udp_total += len(udp_data)
            # check igmp package
            elif ip.p == dpkt.ip.IP_PROTO_IGMP:
                igmp_data = proto
                count_igmp.append(igmp_data)
                igmp_total += len(igmp_data)
        print(f'[+] Number of TCP Packet: {len(count_tcp)}')
        print(f'[+] Number of UDP Packet: {len(count_udp)}')
        print(f'[+] Number of IGMP Packet: {len(count_igmp)}\n')
        print(f'[+] Timestamps First: {time_stamp_list[0]}')
        print(f'[+] Timestamps Last: {time_stamp_list[-1]}\n')
    # Mean packet Length divide with packet type length
        tcp_mean_pac = tcp_total/len(count_tcp)
        print(f'[+] Mean Packet length of TCP: {tcp_mean_pac}')
        udp_mean_pac = udp_total/len(count_udp)
        print(f'[+] Mean Packet length of UDP: {udp_mean_pac}')
        igmp_mean_pac = igmp_total/len(count_igmp)
        print(f'[+] Mean Packet length of UDP: {igmp_mean_pac}\n')
        mean_packet.append((tcp_mean_pac, udp_mean_pac, igmp_mean_pac))
    # enter data into table
        print("TCP Packet Summarize")
        create_table(len(count_tcp),
                     tcp_mean_pac,
                     time_stamp_list[0],
                     time_stamp_list[-1])
        print("UDP Packet Summarize")
        create_table(len(count_udp),
                     udp_mean_pac,
                     time_stamp_list[0],
                     time_stamp_list[-1])
        print("IGMP Packet Summarize")
        create_table(len(count_igmp),
                     igmp_mean_pac,
                     time_stamp_list[0],
                     time_stamp_list[-1])
        return count_tcp, count_udp, count_igmp, time_stamp_list, ip_address, mean_packet


def email_address(count_tcp):
    '''3 a) Find any email address present To and From emails in packet'''
    f_list = []             # empty list for email from packet
    t_list = []

    for count in count_tcp:
        # decode ip.data to get email
        count = count.data.decode("utf-8", "ignore")
        # https://www.dataquest.io/blog/regular-expressions-data-scientists/
        t_email = re.findall("TO:.*", count)
        f_email = re.findall("from:.*", count, re.I)

        # fetch email to packet
        for tem in t_email:
            temail_match = re.findall(r"\<\w\S*@*.\w\>", tem)
            t_list.append(temail_match)
        # fetch email from packet
        for fem in f_email:
            femail_match = re.findall(r"\<\w\S*@*.\w\>", fem)
    for f_em in femail_match:
        f_list.append(f_em)
    # change into dict : key(unique)
    from_email = list(dict.fromkeys(f_list))
    # fetch email address to and from packet
    print(f'[+] Email Address in TO Packet: {t_list}')
    print(f'[+] Email Address in FROM Packet: {from_email}\n')
    return t_list, from_email


def find_url_tcp(count_tcp):
    '''3 c) find url request for all images (.jpg/.png/.gif) from TCP packet'''
    tcp_url = []
    tcp_png = []
    tcp_jpg = []
    tcp_gif = []
    for images_url in count_tcp:
        # decode ip.data to get email
        images_url = images_url.data.decode("utf-8", "ignore")
        url_match = re.findall(
            r"(http[s]?\:\/\/www\.\w+\W?\w+\W?\w+\W?\w+\W?\w+\W?\w+[a-z]+)",
            images_url)
        # fetch (.png/.jpg/.gif) images from TCP packet
        png_match = re.findall(r"\w+\.png", images_url)
        jpg_match = re.findall(r"\w+\.jpg", images_url)
        gif_match = re.findall(r"\w+\.gif", images_url)
        for url_item in url_match:
            if url_item != []:            # remove empty list from url_match
                tcp_url.append(url_item)
        for png_item in png_match:
            if png_item != []:            # remove empty list from url_match
                tcp_png.append(png_item)
        for jpg_item in jpg_match:
            if jpg_item != []:            # remove empty list from url_match
                tcp_jpg.append(jpg_item)
        for gif_item in gif_match:
            if gif_item != []:            # remove empty list from url_match
                tcp_gif.append(gif_item)
    # fetch unique values (no duplicated values)
    # from tcp packet (url,png,jpg,gif)
    from_tcp_url = list(dict.fromkeys(tcp_url))
    from_tcp_png = list(dict.fromkeys(tcp_png))
    from_tcp_jpg = list(dict.fromkeys(tcp_jpg))
    from_tcp_gif = list(dict.fromkeys(tcp_gif))
    # fetch url of all request images(jpg,png,gif) from TCP packet
    print(f'[+] TCP Packet URL: {from_tcp_url}\n')
    print(f'[+] TCP Packet images of .png file: {from_tcp_png}\n')
    print(f'[+] TCP Packet images of .jpg file: {from_tcp_jpg}\n')
    print(f'[+] TCP Packet images of .gif file: {from_tcp_gif}\n')
    return from_tcp_url, from_tcp_png, from_tcp_jpg, from_tcp_gif


def ip_extract(ip_address):
    '''4 Extract the sender and destination IP address pairs for all packets
        and count how many packets were sent from/to each. '''
    # empty list for tcp,udp,igmp src and des
    tcp_list = []
    udp_list = []
    igmp_list = []
    for i in ip_address:
        if i.p == dpkt.ip.IP_PROTO_TCP:                 # check TCP packet
            # change into decimal TCP source, dst ip address
            tcp_src = socket.inet_ntoa(i.src)
            tcp_dst = socket.inet_ntoa(i.dst)
            # enter 2 values into empty list as tuple (src,dst)
            tcp_list.append((tcp_src, tcp_dst))
            tcp_count = dict(Counter(tcp_list))
        # check UDP packet
        elif i.p == dpkt.ip.IP_PROTO_UDP:
            udp_src = socket.inet_ntoa(i.src)
            udp_dst = socket.inet_ntoa(i.dst)
            udp_list.append((udp_src, udp_dst))
            udp_count = dict(Counter(udp_list))
        # check IGMP packet
        elif i.p == dpkt.ip.IP_PROTO_IGMP:
            igmp_src = socket.inet_ntoa(i.src)
            igmp_dst = socket.inet_ntoa(i.dst)
            igmp_list.append((igmp_src, igmp_dst))
            # change to dict count (s,d) is key count(value)
            igmp_count = dict(Counter(igmp_list))
    # sort count, change dict and count largest to smallest
    sort_tcp_count = dict(
        sorted(
            tcp_count.items(),
            key=lambda keyvalue: keyvalue[1],
            reverse=True))
    sort_udp_count = dict(
        sorted(
            udp_count.items(),
            key=lambda keyvalue: keyvalue[1],
            reverse=True))
    sort_igmp_count = dict(
        sorted(
            igmp_count.items(),
            key=lambda keyvalue: keyvalue[1],
            reverse=True))
    # https://stackoverflow.com/questions/613183/how-do-i-sort-a-dictionary-by-value
    # Author: Devin Jeanpierre
    print("[+] TCP Packet Source and Destination IP Address")
    for k, val in sort_tcp_count.items():
    # loop tcp packet src and dst
        print(f"TCP Packet src & dst => {k} \t Count => {val}")
    print("\n")
    print("[+] UDP Packet Source and Destination IP Address")
    for k, val in sort_udp_count.items():
        print(f"UDP Packet src & dst => {k} \t Count => {val}")
    print("\n")
    print("[+] IGMP Packet Source and Destination IP Address")
    for k, val in sort_igmp_count.items():
        print(f"IGMP Packet src & dst => {k} \t Count => {val}\n")
    return sort_tcp_count, sort_udp_count, sort_igmp_count


def main():
    '''main function to called .pcap files, return functions,
       enter all the output into .txt file
       create .json file and enter all packet src and dst.'''
    try:
        pcap = 'evidence-packet-analysis.pcap'
        # pcap = input("Enter pcap file to analyse:")
        print(f'[*] File {pcap} read successfully')
        # recalled functions and return variables
        count_tcp, count_udp, count_igmp, time_stamp_list, ip_address, mean_packet = open_pcap(pcap)
        t_list, from_email = email_address(count_tcp)
        from_tcp_url, from_tcp_png, from_tcp_jpg, from_tcp_gif = find_url_tcp(count_tcp)
        sort_tcp_count, sort_udp_count, sort_igmp_count = ip_extract(ip_address)
        # 5)create a subdirectory inside the current dir,
        # remove dir if its already exist and create new
        # current working directory
        curdir = os.getcwd()
        print(f"Current working Directory {curdir}")
        sub_dir = "json"                                    # dir name
        if not os.path.exists(sub_dir):                     # not exist
            os.mkdir(sub_dir)                               # create dir
            print(f"{sub_dir} is created")
        else:                                               # exist
            print(f"{sub_dir} is already exist")
            # remove previous directory and its contents
            shutil.rmtree(sub_dir)
            # make new dir with the same name
            os.mkdir(sub_dir)
            print(f"Previous directory is deleted and {sub_dir} new directory is created")
            os.chdir(sub_dir)                  # change directory
            print(f"In the new directory {os.getcwd()}")
            # create a file
            with open('json.txt', 'a', encoding="UTF-8") as j:
                # enter packet length
                j.write(f'Number of TCP Packet: {len(count_tcp)} \n')
                j.write(f'Number of TCP Packet: {len(count_udp)} \n')
                j.write(f'Number of TCP Packet: {len(count_igmp)} \n')
                # enter mean packet
                for mean in mean_packet:
                    j.write(f"\nTCP Mean Packet: {str(mean[0])}\n")
                    j.write(f"TCP Mean Packet: {str(mean[1])}\n")
                    j.write(f"TCP Mean Packet: {str(mean[2])}\n")
                # enter first and last timestamp
                j.write(f'\nTimestamps First: {time_stamp_list[0]}')
                j.write(f'\nTimestamps Last: {time_stamp_list[-1]}\n')
                # enter to email packet
                j.write("\nEmail Address in TO Packet:\n")
                for to_em in t_list:
                    for t_e in to_em:
                        j.write(f"{t_e}\n")
                # enter to email packet
                j.write("\nEmail Address in FROM Packet:\n")
                for from_em in from_email:
                    for f_e in from_em:
                        j.write(f"{f_e}\n")
                # enter TCP packet uri (.png, .jpg, .gif file)
                j.write(f"\nTCP Packet URl: {from_tcp_url}\n\n")
                j.write(f"\nTCP Packet images of .png file: \n {from_tcp_png}\n\n")
                j.write(f"\nTCP Packet images of .jpg file: \n {from_tcp_jpg}\n\n")
                j.write(f"\nTCP Packet images of .gif file: \n {from_tcp_gif}\n\n")
                # enter src and dst of everypackets (count and sorted)
                j.write("\nTCP Packet Source and Destination IP Address\n")
                for key, value in sort_tcp_count.items():
                    # loop tcp packet src and dst
                    j.write(f"TCP Packet src and dst => {key} \t Count => {value}\n")
                j.write('\n')
                j.write("\nTCP Packet Source and Destination IP Address\n")
                for key, value in sort_udp_count.items():
                    j.write(f"UDP Packet src and dst => {key} \t Count => {value}\n")
                j.write('\n')
                j.write("\nIGMP Packet Source and Destination IP Address\n")
                for key, value in sort_igmp_count.items():
                    j.write(f"IGMP Packet src and dst => {key} \t Count => {value}\n")
                j.write('\n')
            # .json file for TCP packet ip address
            # sort_tcp_count key is src,dst count is value
            t_dict = {}                               # empty dict
            t_dict.update({"tcp": sort_tcp_count})    # update tcp as key
            tcp = {}
            for value in t_dict["tcp"]:
                # value[0] is ip src , value[1] is ip dst
                tcp_test = f"{value[0]} ... {value[1]}"
                # add key,value into tcp empty dict
                tcp[tcp_test] = t_dict["tcp"][value]
            new_tcp = {"TCP": tcp}
            with open("json.json", "a") as js_f:
                json.dump(new_tcp, js_f, indent=4)
            # .json file for UCP packet ip address
            u_dict = {}
            # add "udp" as key into sort_udp_count to u_dict{}
            u_dict.update({"udp": sort_udp_count})
            # print (y.keys())
            udp = {}
            for value in u_dict["udp"]:
                udp_test = f"{value[0]} ... {value[1]}"
                # {'192.168.30.108 ... 10.30.30.20': 126}...
                udp[udp_test] = u_dict["udp"][value]
            new_udp = {"UDP": udp}
            with open("json.json", "a") as js_f:
                # write into .json indent is for line space
                json.dump(new_udp, js_f, indent=4)
            # .json file for IGMP packet ip address
            i_dict = {}
            i_dict.update({"igmp": sort_igmp_count})
            # print (y.keys())
            igmp = {}
            for value in i_dict["igmp"]:
                # value[0] is ip src , value[1] is ip dst
                igmp_test = f"{value[0]} ... {value[1]}"
                # {'192.168.30.108 ... 10.30.30.20': 126}...
                igmp[igmp_test] = i_dict["igmp"][value]
            new_igmp = {"IGMP": igmp}
            with open("json.json", "a") as js_f:
                json.dump(new_igmp, js_f, indent=4)
    except ZeroDivisionError:
        msg = "Divided by Zero"
        print(msg)
    except OSError:
        msg = "Module error has been occur"
        print(msg)
    except FileNotFoundError:
        msg = "Sorry, File does not exist"
        print(msg)
    except NameError:
        msg = "Unknown Variable name Problem occur"
        print(msg)
    except Exception as err:
        print(f'Exception {err} has occur')


if __name__ == '__main__':
    main()
