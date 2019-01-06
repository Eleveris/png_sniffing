#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <fstream>



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
typedef u_int tcp_seq;

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

static tcp_seq ack=0;
unsigned file_name=0;

void callback (u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet){
    fstream image;
    static unsigned int count = 1;
    cout << count << " packet header: " << endl;
    cout << "Captured: " << hdr->caplen << " from total: " << hdr->len << endl;
    cout << "timestamp: " << hdr->ts.tv_sec << endl;
    count ++;
    pcap_dump(user,hdr,packet);



    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const u_char *payload; /* Packet payload */

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
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    const u_char *png_res = payload;
    //cout << "size: " << SIZE_ETHERNET + size_ip + size_tcp << endl;

    if (ack == 0){
        u_char* vie[8] = {(u_char*)0x89,(u_char*)'P',(u_char*)'N',(u_char*)'G',(u_char*)'\0'};
        u_char* vie2[6] = {(u_char*)0x48,(u_char*)0x54,(u_char*)0x54,(u_char*)0x50,(u_char*)0x2f,(u_char*)0x31};

        auto flags = cout.flags();
        png_res = (u_char *) strstr((char *) payload, (char *)vie);
        const u_char * http_res =(u_char *) strstr((char *) payload, (char *)vie2);

        if (png_res && http_res){
            if ( (png_res[1]!='P') || (png_res[2]!='N') || (png_res[3]!='G') ){
                //cout << "blocked" << endl;
                return;
            }
            ack = tcp->th_ack;
            cout << "hello " << endl;
            file_name=count+(unsigned)ack;
            cout.flags(flags);
        }
    }
    if (ack != 0){
        string name = to_string(file_name) + "img.png";


        auto flag = cout.flags();
        if (tcp->th_ack == ack){
            image.open(name, fstream::out | fstream::app | fstream::binary);
            int i = 0;
            if (!image.is_open()) cout <<"fatal png error" << endl;
            while (&png_res[i] != &packet[hdr->caplen]){
                image << png_res[i];
                //cout << hex << +png_res[i];
                i++;
            }
            cout << "save to "+name;
            cout << endl;
            u_char *vie3[5]={(u_char*)'I',(u_char*)'E',(u_char*)'N',(u_char*)'D',(u_char* )'\0'};
            u_char *end_check;
            end_check = (u_char *)strstr((char *)(packet+hdr->caplen-8),(char *)vie3);
            if (end_check) {
                //cout << "end pack try" << endl;
                if ((end_check[1] == 'E') && (end_check[2] == 'N') && (end_check[3] == 'D')) {
                    ack = 0;
                    file_name = 0;

                    cout << "ending png packet" << endl;
                }
            }
            cout << endl << "png packet" << endl;
            image.flush();
            image.close();
        }
        cout.flags(flag);

    }

}//0x7fff8150fc10

int main(int argc, char* argv[]) {
    cout << "Hello, World!" << endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    int errcode;
    string ask;


//    cout << "Print available devices? (Y/n):" << endl; //device list
//    cin >> ask;
//
//    cout << endl;
//    if ((ask == "y") or (ask == "Y")) {
//        vector<pcap_if_t *> devices;
//        list_devices(devices);
//    }

    string dev;
    const char* devc;
    pcap_t *p;
//    cout << "Print device: " << endl; //device input
//    cin >> dev;
//    devc = (char*)dev.c_str();

    const char* devic = "wlx7062b8b49c52";
    p = pcap_create(devic,errbuf);

    const int snaplen = 65536;
    errcode = pcap_set_snaplen(p,snaplen);
    //cout << "pcap_set_snaplen error code: " << errcode << endl;
    errcode = pcap_set_promisc(p, 1);
    //cout << "pcap_set_promisc error code: " << errcode << endl;
//
//    cout << "Print domain: ";
//    cin >> ask;
//    ask="tcp port 80 and host "+ask;
    //const char* fil = ask.c_str();

    const char *errDescr;
    errcode = pcap_activate(p);
    if (errcode != 0){
        errDescr = pcap_statustostr(errcode);
        cout << "pcap error: " << errDescr;
    }
    else cout << "capturing" << endl;

    char *error;
    const char *filename = "packets.pcap";
    pcap_dumper_t *fileDumper;
    fileDumper = pcap_dump_open(p, filename);
    if (fileDumper == NULL)
        error = pcap_geterr(p);


    //place for filtres

    bpf_program *bpf;


    const char* fi = "tcp port 80 and host libpng.org";
    int comp_optim = 1;
    bpf_u_int32 netmask;
    if (pcap_compile(p,bpf,fi,comp_optim,netmask) != 0){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", "we fucked up", pcap_geterr(p));
        return(2);
    };

    pcap_setfilter(p,bpf);


    int count = -1;
    errcode = pcap_loop(p,count,callback, (u_char *) fileDumper);
    if (errcode != 0) {
        errDescr = pcap_statustostr(errcode);
        std::cout << "capturing error! ";
        std::cout << errDescr << std::endl;
    } else std::cout << "capturing ended" << std::endl;

    pcap_dump_close(fileDumper);
    pcap_freecode(bpf);

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
