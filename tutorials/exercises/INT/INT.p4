#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<8>  TCP_PROTOCOL = 0x06;
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> INT_PORT = 0x12b6;
const bit<32> REPORT_MIRROR_SESSION_ID = 500;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16>   srcPort;
    bit<16>   int_dstPort;
    bit<16>   length;
    bit<16>   checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> int_dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header int_header_t {
    bit<2>    ver;
    bit<2>    rep;
    bit<1>    c;
    bit<1>    e;
    bit<5>    rsvd1;
    bit<5>    ins_cnt;
    bit<8>    max_hop_cnt;
    bit<8>    total_hop_cnt;
    bit<4>    instruction_mask_0003;
    bit<4>    instruction_mask_0407;
    bit<4>    instruction_mask_0811;
    bit<4>    instruction_mask_1215;
    bit<16>   rsvd2;
    bit<16>   int_length;
    bit<16>   udp_or_tcp_dstPort;
}

header int_switch_id_header_t {
//    bit<1>    bos;
    bit<8>   switch_id;
}

header int_ingress_port_header_t {
//    bit<1>    bos;
    bit<16>   ingress_port;
    bit<16>   ingress_port_count;
}

header int_ingress_global_timestamp_header_t {
//    bit<1>    bos;
    bit<56>   ingress_global_timestamp;
}

header int_enq_qdepth_header_t {
//    bit<1>    bos;
    bit<24>   enq_qdepth;
}

header int_deq_timedelta_header_t {
//   bit<1>    bos;
    bit<40>   deq_timedelta;
}

header int_deq_qdepth_header_t {
//    bit<1>    bos;
    bit<24>   deq_qdepth;
}

header int_egress_global_timestamp_header_t {
//    bit<1>    bos;
    bit<56>   egress_global_timestamp;
}

header int_egress_port_header_t {
//   bit<1>    bos;
    bit<16>   egress_port;
    bit<16>   egress_port_count;
}

header int_meta_t {
    varbit<2072> int_metadata;
}

struct meta_t {
    bit<8>    switch_id;
    bit<16>   ingress_port;
    bit<56>   ingress_global_timestamp;
    bit<24>   enq_qdepth;
    bit<40>   deq_timedelta;
    bit<24>   deq_qdepth;
    bit<56>   egress_global_timestamp;
    bit<16>   egress_port;
    bit<32>   ingress_port_counter_index;
    bit<16>   ingress_port_counter_count;
    bit<32>   egress_port_counter_index;
    bit<16>   egress_port_counter_count;
    bit<16>   sport;
    bit<16>   dport;
    bit<16>   udp_or_tcp_dstPort;
    bit<2>    int_flag;  //0 forward 1 source 2 sink	
    bit<1>    clone_flag; //0 clone 1 normal
}

struct metadata {
    meta_t meta;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    tcp_t tcp;
    int_header_t int_header;
    int_switch_id_header_t int_switch_id_header;
    int_ingress_port_header_t int_ingress_port_header;
    int_ingress_global_timestamp_header_t int_ingress_global_timestamp_header;
    int_enq_qdepth_header_t int_enq_qdepth_header;
    int_deq_timedelta_header_t int_deq_timedelta_header;
    int_deq_qdepth_header_t int_deq_qdepth_header;
    int_egress_global_timestamp_header_t int_egress_global_timestamp_header;
    int_egress_port_header_t int_egress_port_header;
    int_meta_t int_meta;
}

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: reject;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select(hdr.ipv4.protocol) {
            UDP_PROTOCOL  : parser_udp;
            TCP_PROTOCOL  : parser_tcp;
            default       : reject;
        }
    }

    state parser_udp {
        packet.extract(hdr.udp);
	meta.meta.sport=hdr.udp.srcPort;
	meta.meta.dport=hdr.udp.int_dstPort;
        transition select(hdr.udp.int_dstPort) {
            INT_PORT  : parser_int_header;
            default   : accept;
        }
    }

    state parser_tcp {
        packet.extract(hdr.tcp);
	meta.meta.sport=hdr.tcp.srcPort;
	meta.meta.dport=hdr.tcp.int_dstPort;
        transition select(hdr.tcp.int_dstPort) {
            INT_PORT  : parser_int_header;
            default   : accept;
        }
    }

    state parser_int_header {
        packet.extract(hdr.int_header);
	meta.meta.dport=hdr.int_header.udp_or_tcp_dstPort;
        transition parser_int_meta;
    }

    state parser_int_meta {
          packet.extract(hdr.int_meta,(bit<32>)(((bit<16>)hdr.int_header.int_length-12)*8));
          transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    register<bit<16>>(32w16) ingress_port_counter;

    action drop() {
        mark_to_drop();
    }

    action set_counter() {
        hash(meta.meta.ingress_port_counter_index, HashAlgorithm.crc16,
             (bit<16>) 0, {hdr.ipv4.srcAddr,
		      	   hdr.ipv4.dstAddr,
			   meta.meta.sport,
	 		   meta.meta.dport,
			   hdr.ipv4.protocol},
             (bit<32>) 16);
	ingress_port_counter.read(meta.meta.ingress_port_counter_count,meta.meta.ingress_port_counter_index);
	meta.meta.ingress_port_counter_count=meta.meta.ingress_port_counter_count+1;
	ingress_port_counter.write(meta.meta.ingress_port_counter_index,meta.meta.ingress_port_counter_count);
    }

    action forward(egressSpec_t port,bit<2> flag) {
        standard_metadata.egress_spec = port;
	meta.meta.udp_or_tcp_dstPort = 4790;
	meta.meta.int_flag = flag;
	meta.meta.clone_flag = 1;
	set_counter();
//        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table  tbl_forward {
        key = {
            hdr.ipv4.srcAddr: exact;
	    hdr.ipv4.dstAddr: exact;
	    hdr.ipv4.protocol: exact;
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            tbl_forward.apply();
        }
	if (meta.meta.int_flag==2) {
	    clone(CloneType.I2E,REPORT_MIRROR_SESSION_ID);	
	}
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action source_modify() {
        hdr.udp.int_dstPort=meta.meta.udp_or_tcp_dstPort;
        hdr.tcp.int_dstPort=meta.meta.udp_or_tcp_dstPort;
    }

    action source_set() {
//****************** INT INITIALATION ********************************//
	hdr.int_header.setValid();
        hdr.int_header.ver=0;
        hdr.int_header.rep=0;
        hdr.int_header.c=0;
        hdr.int_header.e=0;
        hdr.int_header.rsvd1=0;
        hdr.int_header.ins_cnt=8;
        hdr.int_header.max_hop_cnt=5;
        hdr.int_header.total_hop_cnt=0;
        hdr.int_header.instruction_mask_0003=15;
        hdr.int_header.instruction_mask_0407=15;
        hdr.int_header.instruction_mask_0811=0;
        hdr.int_header.instruction_mask_1215=0;
        hdr.int_header.rsvd2=0;
        hdr.int_header.int_length=12;  //8bit
        hdr.int_header.udp_or_tcp_dstPort=meta.meta.dport;
	source_modify();
    }

    table source_init {
        key = {
            meta.meta.int_flag : exact;
        }
        actions = {
            source_set;
            NoAction;
        }
	default_action = NoAction;
    }


    action int_set_header_0() {
        hdr.int_switch_id_header.setValid();
        hdr.int_switch_id_header.switch_id=meta.meta.switch_id;;
        hdr.int_header.int_length=hdr.int_header.int_length+1;
    }

    action int_set_header_1() {
        hdr.int_ingress_port_header.setValid();
        hdr.int_ingress_port_header.ingress_port=meta.meta.ingress_port;
	hdr.int_ingress_port_header.ingress_port_count=meta.meta.ingress_port_counter_count;
        hdr.int_header.int_length=hdr.int_header.int_length+4;
    }

    action int_set_header_2() {
        hdr.int_ingress_global_timestamp_header.setValid();
        hdr.int_ingress_global_timestamp_header.ingress_global_timestamp=meta.meta.ingress_global_timestamp;
        hdr.int_header.int_length=hdr.int_header.int_length+7;
    }

    action int_set_header_3() {
        hdr.int_enq_qdepth_header.setValid();
        hdr.int_enq_qdepth_header.enq_qdepth=meta.meta.enq_qdepth;
        hdr.int_header.int_length=hdr.int_header.int_length+3;
    }

    action int_set_header_4() {
        hdr.int_deq_timedelta_header.setValid();
        hdr.int_deq_timedelta_header.deq_timedelta=meta.meta.deq_timedelta;
        hdr.int_header.int_length=hdr.int_header.int_length+5;
    }

    action int_set_header_5() {
        hdr.int_deq_qdepth_header.setValid();
        hdr.int_deq_qdepth_header.deq_qdepth=meta.meta.deq_qdepth;
        hdr.int_header.int_length=hdr.int_header.int_length+3;
    }

    action int_set_header_6() {
        hdr.int_egress_global_timestamp_header.setValid();
        hdr.int_egress_global_timestamp_header.egress_global_timestamp=meta.meta.egress_global_timestamp;
        hdr.int_header.int_length=hdr.int_header.int_length+7;
    }

    action int_set_header_7() {
        hdr.int_egress_port_header.setValid();
        hdr.int_egress_port_header.egress_port=meta.meta.egress_port;
	hdr.int_egress_port_header.egress_port_count=meta.meta.egress_port_counter_count;
        hdr.int_header.int_length=hdr.int_header.int_length+4;
    }
/*
    action int_set_bos_0() {
        hdr.int_switch_id_header.bos=1;
    }

    action int_set_bos_1() {
        hdr.int_ingress_port_header.bos=1;
    }

    action int_set_bos_2() {
        hdr.int_ingress_global_timestamp_header.bos=1;
    }

    action int_set_bos_3() {
        hdr.int_enq_qdepth_header.bos=1;
    }

    action int_set_bos_4() {
        hdr.int_deq_timedelta_header.bos=1;
    }

    action int_set_bos_5() {
        hdr.int_deq_qdepth_header.bos=1;
    }

    action int_set_bos_6() {
        hdr.int_egress_global_timestamp_header.bos=1;
    }

    action int_set_bos_7() {
        hdr.int_egress_port_header.bos=1;
    }
*/
    register<bit<16>>(32w16) egress_port_counter;

    action set_counter() {
        hash(meta.meta.egress_port_counter_index, HashAlgorithm.crc16,
             (bit<16>) 0, {hdr.ipv4.srcAddr,
		      	   hdr.ipv4.dstAddr,
			   meta.meta.sport,
	 		   meta.meta.dport,
			   hdr.ipv4.protocol},
             (bit<32>) 16);
	egress_port_counter.read(meta.meta.egress_port_counter_count,meta.meta.egress_port_counter_index);
	meta.meta.egress_port_counter_count=meta.meta.egress_port_counter_count+1;
	egress_port_counter.write(meta.meta.egress_port_counter_index,meta.meta.egress_port_counter_count);
    }

    action int_set_metadata(bit<8> switch_id) {
        meta.meta.switch_id=switch_id;
        meta.meta.ingress_port=(bit<16>)standard_metadata.ingress_port;
        meta.meta.ingress_global_timestamp=(bit<56>)standard_metadata.egress_global_timestamp;
        meta.meta.enq_qdepth=(bit<24>)standard_metadata.enq_qdepth;
        meta.meta.deq_timedelta=(bit<40>)standard_metadata.deq_timedelta;
        meta.meta.deq_qdepth=(bit<24>)standard_metadata.deq_qdepth;
        meta.meta.egress_global_timestamp=(bit<56>)standard_metadata.ingress_global_timestamp;
        meta.meta.egress_port=(bit<16>)standard_metadata.egress_port;
	meta.meta.dport=hdr.int_header.udp_or_tcp_dstPort;
	set_counter();
    }

    table int_inst {
        actions = {
        int_set_metadata;
        }
    }

    table int_inst_0 {
        actions = {
        int_set_header_0;
        }
        default_action=int_set_header_0();
    }

    table int_inst_1 {
        actions = {
        int_set_header_1;
        }
        default_action=int_set_header_1();
    }

    table int_inst_2 {
        actions = {
        int_set_header_2;
        }
        default_action=int_set_header_2();
    }

    table int_inst_3 {
        actions = {
        int_set_header_3;
        }
        default_action=int_set_header_3();
    }

    table int_inst_4 {
        actions = {
        int_set_header_4;
        }
        default_action=int_set_header_4();
    }

    table int_inst_5 {
        actions = {
        int_set_header_5;
        }
        default_action=int_set_header_5();
    }

    table int_inst_6 {
        actions = {
        int_set_header_6;
        }
        default_action=int_set_header_6();
    }

    table int_inst_7 {
        actions = {
        int_set_header_7;
        }
        default_action=int_set_header_7();
    }
/*
    table int_bos_0 {
        actions = {
        int_set_bos_0;
        }
        default_action=int_set_bos_0();
    }

    table int_bos_1 {
        actions = {
        int_set_bos_1;
        }
        default_action=int_set_bos_1();
    }

    table int_bos_2 {
        actions = {
        int_set_bos_2;
       }
       default_action=int_set_bos_2();
    }

    table int_bos_3 {
        actions = {
        int_set_bos_3;
        }
        default_action=int_set_bos_3();
    }

    table int_bos_4 {
        actions = {
        int_set_bos_4;
        }
        default_action=int_set_bos_4();
    }

    table int_bos_5 {
        actions = {
        int_set_bos_5;
        }
        default_action=int_set_bos_5();
    }

    table int_bos_6 {
        actions = {
        int_set_bos_6;
        }
        default_action=int_set_bos_6();
    }

    table int_bos_7 {
        actions = {
        int_set_bos_7;
        }
        default_action=int_set_bos_7();
    }
*/
    action sink_modify() {
	hdr.udp.int_dstPort=meta.meta.dport;
       	hdr.tcp.int_dstPort=meta.meta.dport;
    }

    action sink_set() {
	hdr.int_header.setInvalid();
        hdr.int_meta.setInvalid();
	hdr.int_switch_id_header.setInvalid();
	hdr.int_ingress_port_header.setInvalid();
	hdr.int_ingress_global_timestamp_header.setInvalid();
	hdr.int_enq_qdepth_header.setInvalid();
	hdr.int_deq_timedelta_header.setInvalid();
	hdr.int_deq_qdepth_header.setInvalid();
	hdr.int_egress_global_timestamp_header.setInvalid();
	hdr.int_egress_port_header.setInvalid();
	sink_modify();
    }

    table sink_init {
        key = {
	    meta.meta.clone_flag : exact;
        }
        actions = {
            sink_set;
            NoAction;
        }
	default_action = NoAction;
    }

    apply {
	source_init.apply();
	if(hdr.int_header.isValid()) {
        int_inst.apply();

        if ((hdr.int_header.instruction_mask_0003 & 0x8) != 0)
              int_inst_0.apply();
          if ((hdr.int_header.instruction_mask_0003 & 0x4) != 0)
              int_inst_1.apply();
          if ((hdr.int_header.instruction_mask_0003 & 0x2) != 0)
              int_inst_2.apply();
          if ((hdr.int_header.instruction_mask_0003 & 0x1) != 0)
              int_inst_3.apply();
          if ((hdr.int_header.instruction_mask_0407 & 0x8) != 0)
              int_inst_4.apply();
          if ((hdr.int_header.instruction_mask_0407 & 0x4) != 0)
              int_inst_5.apply();
          if ((hdr.int_header.instruction_mask_0407 & 0x2) != 0)
              int_inst_6.apply();
          if ((hdr.int_header.instruction_mask_0407 & 0x1) != 0)
              int_inst_7.apply();
/*
          if (hdr.int_header.total_hop_cnt == 0) {
              if ((hdr.int_header.instruction_mask_0407 & 0x1) != 0) {
                  int_bos_7.apply();
              } else if ((hdr.int_header.instruction_mask_0407 & 0x2) != 0) {
                  int_bos_6.apply();
              } else if ((hdr.int_header.instruction_mask_0407 & 0x4) != 0) {
                  int_bos_5.apply();
              } else if ((hdr.int_header.instruction_mask_0407 & 0x8) != 0) {
                  int_bos_4.apply();
              } else if ((hdr.int_header.instruction_mask_0003 & 0x1) != 0) {
                  int_bos_3.apply();
              } else if ((hdr.int_header.instruction_mask_0003 & 0x2) != 0) {
                  int_bos_2.apply();
              } else if ((hdr.int_header.instruction_mask_0003 & 0x4) != 0) {
                  int_bos_1.apply();
              } else if ((hdr.int_header.instruction_mask_0003 & 0x8) != 0) {
                  int_bos_0.apply();
              }
          }
*/
        }
	sink_init.apply();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	            hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_switch_id_header);
        packet.emit(hdr.int_ingress_port_header);
        packet.emit(hdr.int_ingress_global_timestamp_header);
        packet.emit(hdr.int_enq_qdepth_header);
        packet.emit(hdr.int_deq_timedelta_header);
        packet.emit(hdr.int_deq_qdepth_header);
        packet.emit(hdr.int_egress_global_timestamp_header);
        packet.emit(hdr.int_egress_port_header);
	packet.emit(hdr.int_meta);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
