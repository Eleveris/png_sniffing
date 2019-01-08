#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <list>

#include <cstdint>
#include <cstring>


#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <arpa/inet.h>

using namespace std;

#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef uint32_t tcp_seq;

struct sniff_tcp {
    u_short th_sport;    /* source port */
    u_short th_dport;    /* destination port */
    tcp_seq th_seq;        /* sequence number */
    tcp_seq th_ack;        /* acknowledgement number */
    u_char th_offx2;    /* data offset, rsvd */
#define TH_OFF(th)    (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;        /* window */
    u_short th_sum;        /* checksum */
    u_short th_urp;        /* urgent pointer */
};

#define SIZE_ETHERNET 14


void list_devices(vector <pcap_if_t *> &devices);

vector <tcp_seq> ack,seq;
vector <unsigned> file_name;

void callback (u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet){
    cout <<"callback started\n";
    fstream image;
    static unsigned int count = 1;
    cout << count << " packet header: " << endl;
    cout << "Captured: " << hdr->caplen << " from total: " << hdr->len << endl;
    cout << "timestamp: " << hdr->ts.tv_sec << endl;
    count ++;
    cout <<"dump\n";
    pcap_dump(user,hdr,packet);
    cout <<"dumped\n";


    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    u_char *payload; /* Packet payload */

    u_int size_ip;
    u_int size_tcp;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    cout << "size tcp: "<< size_tcp << endl;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    if ((hdr->caplen-SIZE_ETHERNET-size_ip-size_tcp) <= 32){
        cout << "packet looks to small" << endl;
        return;
    }
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    u_char *png_res = payload;
    //cout << "size: " << SIZE_ETHERNET + size_ip + size_tcp << endl;


    u_char* vie[4] = {(u_char*)0x89,(u_char*)'P',(u_char*)'N',(u_char*)'G'};
    u_char* vie2[6] = {(u_char*)0x48,(u_char*)0x54,(u_char*)0x54,(u_char*)0x50,(u_char*)0x2f,(u_char*)0x31};

    cout << "png check try" << endl;
    auto flags = cout.flags();
    cout << "before: " << &png_res << endl << "and payload: "<< &payload << endl;
    png_res = (u_char *) strstr((char *) payload, (char *)vie);
    cout << "after: " << &png_res << endl;
    const u_char * http_res =(u_char *) strstr((char *) payload, (char *)vie2);

    if (png_res && http_res){
        if ( (png_res[1]!='P') || (png_res[2]!='N') || (png_res[3]!='G') || (png_res[4]!=0x0d) || (png_res[5]!=0x0a) || (png_res[6]!=0x1a) || (png_res[7]!=0x0a) ){
            png_res=payload;
            cout << "blocked" << endl;
        }
        else {
            cout << "png start passed ack: " << (u_long)tcp->th_ack << " seq: " << (u_long)tcp->th_seq << endl;
            seq.push_back(ntohl(tcp->th_seq));
            ack.push_back(tcp->th_ack);
            cout << "hello "<< count << endl;
            file_name.push_back(count+(unsigned)tcp->th_ack);
            cout.flags(flags);
        }
    }
    else png_res=payload;
    cout << "ack check" << endl;
    if (!ack.empty()){
        auto ack_iter = find(ack.begin(),ack.end(),tcp->th_ack);
        if (ack_iter == ack.end()){
            cout << "not png's packet or not marked packet\n";
            return;
        }
        long index = distance(ack.begin(),ack_iter);
        auto file_name_iter = file_name.begin();
        auto seq_iter = seq.begin();
        advance(file_name_iter,index);
        advance(seq_iter,index);

        string name = to_string(file_name.at(index)) + "img.png";

        cout << "test\n" << (u_short)tcp->th_seq << endl << tcp->th_seq << endl << ntohl(tcp->th_seq) << endl;
        auto flag = cout.flags();

        if (ntohl(tcp->th_seq)==seq.at(index)){
            cout << "good packet" <<endl;
            seq.at(index)+=1448;
            cout << "next seq: "<< seq.at(index);
        }
        else {
            cout << "bad packet"<<endl;
            return;
        }

        image.open(name, fstream::out | fstream::app | fstream::binary);
        int i = 0;
        if (!image.is_open()) {
            cout <<"fatal png error" << endl;
            return;
        }
        else cout << "writing to file" << endl;

        bool first = true;
        while (&png_res[i] < &packet[hdr->caplen]) {

            if (first){
                cout << "first" << endl;
                cout << hex << +png_res[i];
                cout << "not last"<< endl;
                first = false;
            }
            image << png_res[i];
            cout << hex << +png_res[i] << " ";
            i++;
        }
        cout <<endl;

        cout << "save to "+name;
        cout << endl;
        u_char *vie3[5]={(u_char*)'I',(u_char*)'E',(u_char*)'N',(u_char*)'D',(u_char* )'\0'};
        u_char *end_check;
        end_check = (u_char *)strstr((char *)(packet+hdr->caplen-8),(char *)vie3);
        if (end_check) {
            //cout << "end pack try" << endl;
            if ((end_check[1] == 'E') && (end_check[2] == 'N') && (end_check[3] == 'D')) {
                ack.erase(ack_iter);
                file_name.erase(file_name_iter);
                seq.erase(seq_iter);
                cout << "ending png packet" << endl;
            }
        }
        cout << endl << "png packet" << endl;
        image.flush();
        image.close();

        cout.flags(flag);
    }
    else cout << "ack empty" << endl;

}//0x7fff8150fc10

int main(int argc, char* argv[]) {
    cout << "Hello, World!" << endl;
    char errbuf[PCAP_ERRBUF_SIZE];
    int errcode;
    pcap_t *p;


    //begin device
    cout << "begin devices\n";
    cout << "Print available devices? (Y/n):" << endl; //device list
    char ask[30];
    cin >> ask;
    cout << ask << endl;
    if ((ask[0] == 'y') or (ask[0] == 'Y')) {
        vector<pcap_if_t *> devices;
        list_devices(devices);
    }

    //palce for device input
    cout << "print device name\n";
    char input_device[30];
    cin >> input_device;

    const char* device = "wlx7062b8b49c52";
    p = pcap_create(input_device,errbuf);
    const int snaplen = 65536;
    errcode = pcap_set_snaplen(p,snaplen);
    cout << "pcap_set_snaplen error code: " << errcode << endl;
    errcode = pcap_set_promisc(p, 1);
    cout << "pcap_set_promisc error code: " << errcode << endl;
    //end device


    cout << "begin activate\n";
    const char * errDescription;
    errcode = pcap_activate(p);
    if (errcode != 0){
        errDescription = pcap_statustostr(errcode);
        cout << "pcap error : " << errDescription <<"\n";
        return 2;

    }
    else cout <<"pcap activated\n";

    //begin filters
    cout << "begin filers\n";
    cout << "print host: \n";
    char host [40];
    cin >> host;
    const char filter_inp[45] = "tcp port 80 and host ";
    char * result_filter = (char *)malloc(sizeof(filter_inp)+sizeof(host)+1);
    sprintf(result_filter, "%s%s", filter_inp, host);
    //cout << result_filter;
    auto * bpf = (bpf_program*) malloc(sizeof(bpf_program));
    //const char filter[40] = "tcp port 80 and host libpng.org";
    int comp_optim = 1;
//    bpf_u_int32 netmask;

    if (pcap_compile(p,bpf,result_filter,comp_optim,PCAP_NETMASK_UNKNOWN) != 0){
        cout << "Couldn't parse filter:\n" << pcap_geterr(p);
        return 2;
    }
    pcap_setfilter(p,bpf);
    //end filters

    //begin file dumper
    cout << "begin file dumper\n";
    char *error;
    const char *filename = "packets.pcap";
    pcap_dumper_t * file_dumper;
    file_dumper = pcap_dump_open(p,filename);
    if (file_dumper == nullptr){
        error = pcap_geterr(p);
        cout << error;
        return 3;
    }
    //end file dumper

    cout << "begin capturing...\n";
    int count = -1;
    errcode = pcap_loop(p,count,callback,(u_char *) file_dumper);
    if (errcode != 0){
        errDescription = pcap_statustostr(errcode);
        cout  << "capturing error! \n" << errDescription << "\n";
    }
    else cout << "capturing ended\n";
    pcap_dump_close(file_dumper);
    pcap_freecode(bpf);
    free(bpf);

    return 0;
}

void list_devices(vector <pcap_if_t *> &devices){
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int errcode;

    errcode = pcap_findalldevs(&device,errbuf);
    if (errcode == 0){
        while (device){
            devices.push_back(device);
            cout << "Name: " << device->name << endl;
            cout << "Addresses: " << device->addresses << endl;
            if (device->description){
                cout << "Description: " << device->description << endl;
            }
            else cout << "No description" << endl;
            device = device->next;
        }
    }
    else {
        cout << "No devices, code: " << errcode;
    }
    pcap_freealldevs(device);

}
