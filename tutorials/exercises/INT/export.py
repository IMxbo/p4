#!/usr/bin/python2.7
#for UDP or TCP
import sys
import time
import pcapy
import pandas as pd
from pcapfile import savefile
from collections import OrderedDict
import table
from prometheus_client import start_http_server,Gauge

g=Gauge('Test_date1','A test date from virtual',['s','p'])
start_http_server(8003)
#g2=Gauge('Test_date2','A test date from virtual')
#g3=Gauge('Test_date3','A test date from virtual')
#g4=Gauge('Test_date4','A test date from virtual')
#g5=Gauge('Test_date5','A test date from virtual')
#g6=Gauge('Test_date6','A test date from virtual')
#g7=Gauge('Test_date7','A test date from virtual')



#
hdr_eth=OrderedDict()
hdr_ipv4=OrderedDict()
hdr_tcp=OrderedDict()
hdr_udp=OrderedDict()
#hdr_vxlan_gpe=OrderedDict()
#hdr_vxlan_gpe_int=OrderedDict()
hdr_int_header=OrderedDict()
hdr_int_switch_id=OrderedDict()
hdr_int_ingress_port=OrderedDict()
hdr_int_ingress_ts=OrderedDict()
hdr_int_enq_depth=OrderedDict()
hdr_int_deq_timedelta=OrderedDict()
hdr_int_deq_depth=OrderedDict()
hdr_int_egress_ts=OrderedDict()
hdr_int_egress_port=OrderedDict()

#
hdr_eth['dstAddr']=48
hdr_eth['srcAddr']=48
hdr_eth['etherType']=16

hdr_ipv4['version']=4
hdr_ipv4['ihl']=4
hdr_ipv4['diffserv']=8
hdr_ipv4['totalLen']=16
hdr_ipv4['identification']=16
hdr_ipv4['flags']=3
hdr_ipv4['fragOffset']=13
hdr_ipv4['ttl']=8
hdr_ipv4['protocol']=8
hdr_ipv4['hdrChecksum']=16
hdr_ipv4['srcAddr1']=8
hdr_ipv4['srcAddr2']=8
hdr_ipv4['srcAddr3']=8
hdr_ipv4['srcAddr4']=8
hdr_ipv4['dstAddr1']=8
hdr_ipv4['dstAddr2']=8
hdr_ipv4['dstAddr3']=8
hdr_ipv4['dstAddr4']=8



hdr_tcp['srcPort']=16
hdr_tcp['int_dstPort']=16
hdr_tcp['seqNo']=32
hdr_tcp['ackNo']=32
hdr_tcp['data0ffset']=4
hdr_tcp['res']=3
hdr_tcp['ecn']=3
hdr_tcp['ctrl']=6
hdr_tcp['window']=16
hdr_tcp['checksum']=16
hdr_tcp['urgentPtr']=16

hdr_udp['srcPort']=16
hdr_udp['dstPort']=16
hdr_udp['length']=16
hdr_udp['checksum']=16


#hdr_vxlan_gpe['flags']=8
#hdr_vxlan_gpe['reserved']=16
#hdr_vxlan_gpe['next_proto']=8
#hdr_vxlan_gpe['vni']=24
#hdr_vxlan_gpe['reserved2']=8

#hdr_vxlan_gpe_int['int_type']=8
#hdr_vxlan_gpe_int['rsvd']=8
#hdr_vxlan_gpe_int['len']=8
#hdr_vxlan_gpe_int['next_proto']=8

hdr_int_header['ver']=2
hdr_int_header['rep']=2
hdr_int_header['c']=1
hdr_int_header['e']=1
hdr_int_header['rsvd1']=5
hdr_int_header['ins_cnt']=5
hdr_int_header['max_hop_cnt']=8
hdr_int_header['total_hop_cnt']=8
hdr_int_header['instruction_mask_0003']=4
hdr_int_header['instruction_mask_0407']=4
hdr_int_header['instruction_mask_0811']=4
hdr_int_header['instruction_mask_1215']=4
hdr_int_header['rsvd2']=16
hdr_int_header['int_length']=16
hdr_int_header['udp_or_tcp_dstport']=16

#hdr_int_switch_id['bos']=1
hdr_int_switch_id['switch_id']=8

#hdr_int_ingress_port['bos']=1
hdr_int_ingress_port['ingress_port']=16
hdr_int_ingress_port['ingress_port_count']=16

#hdr_int_ingress_ts['bos']=1
hdr_int_ingress_ts['ingress_ts']=56

#hdr_int_enq_depth['bos']=1
hdr_int_enq_depth['enq_depth']=24

#hdr_int_deq_timedelta['bos']=1
hdr_int_deq_timedelta['deq_timedelta']=40

#hdr_int_deq_depth['bos']=1
hdr_int_deq_depth['deq_depth']=24

#hdr_int_egress_ts['bos']=1
hdr_int_egress_ts['egress_ts']=56

#hdr_int_egress_port['bos']=1
hdr_int_egress_port['egress_port']=16
hdr_int_egress_port['egress_port_count']=16

#
egress_ts=0
in_ts=0
switch_id=0
n=0
#
def header_display(a):
	
	dataframe =pd.DataFrame({'Pktno':Pktno,'length':a[0],'switch_id':a[1],'ingress_port':a[2],'ingress_tS':a[3],\
	'enq_depth':a[4],'deq_timedelt':a[5],'deq_depth':a[6],'egress_tS':a[7],'egress_port':a[8],'delta_ts':a[9],'srcAddr':a[10],'dstAddr':a[11],'version':a[12],'srcPort':a[13],'dstPort':a[14],'link_ts':a[15],'pswitch_id':a[16]})
	cols=['Pktno','switch_id','pswitch_id','delta_ts','deq_timedelt','link_ts','ingress_port','ingress_tS','enq_depth','deq_depth','egress_tS','egress_port','length','srcAddr','dstAddr','version','srcPort','dstPort']
	dataframe=dataframe.ix[:,cols]
        dataframe.to_csv("test2.csv",mode='a',index=False,header=False)
	    
	    	
def header_print(hdr,hdrname,indent_amount,compact=True):
    I=indent_amount*" "
    m=0
    if compact==False:
        print I+"___________________"
        print I+hdrname
        print I+"___________________"
        for fld,fldobj in hdr.items():
            print I+"%s[%d]=0x%x"%(fld,fldobj['width'],fldobj['value'])
    else:
        print I+hdrname+" |", #
        for fld,fldobj in hdr.items():
            print "%s : 0x%x |" %(fld,fldobj['value']),
        print ""

def header_extract(hdr_def,data_obj): #
    leftover_width=0
    leftover_value=0
    ret=OrderedDict()

    for fld,width in hdr_def.items():
        toget=width
        field_offset=0
        field_value=0

        ret[fld]={'width':width}

        while toget:
            if leftover_width:
                chunk_width=min(leftover_width,toget)
                leftover_width=leftover_width-chunk_width
                chunk_value=leftover_value>>leftover_width
                leftover_value=leftover_value&(((1<<chunk_width)-1)<<leftover_width)
            else:
                chunk_width=min(8,toget)
                chunk_value=ord(data_obj['data'][data_obj['offset']]) 
                if chunk_width!=8:
                    leftover_width=8-chunk_width
                    leftover_value=chunk_value&((1<<leftover_width)-1)
                    chunk_value>>=leftover_width

                data_obj['offset']+=1
            field_value|=chunk_value<<(toget-chunk_width)
            toget-=chunk_width
        ret[fld]['value']=field_value

    if leftover_width:
        print "bad header definition - not byte aligned"
        sys.exit(1)

    return ret
       
    
#
def process_int_pkt(pkt_data):

    global dstAddr
    global srcAddr
    global version
    global srcPort
    global dstPort
    
    global switch_id
    global ingress_port
    global ingress_port_count
    global ingress_ts
    global enq_depth
    global deq_timedelta
    global deq_depth
    global egress_ts
    global egress_port
    global egress_port_count
    global delta_ts
    global link_ts
    global in_ts
    global pswitch_id
    global n
    DstAddr=[]
    SrcAddr=[]
    Version=[]
    SrcPort=[]
    DstPort=[]
    
    Switch_id=[]
    Ingress_port=[]
    Ingress_port_count=[]
    Ingress_ts=[]
    Enq_depth=[]
    Deq_timedelta=[]
    Deq_depth=[]
    Egress_ts=[]
    Egress_port=[]
    Egress_port_count=[]
    Delta_ts=[]
    Length=[]
    Link_ts=[]
    Pswitch_id=[]
    a=[Length,Switch_id,Ingress_port,Ingress_ts,Enq_depth,Deq_timedelta,Deq_depth,Egress_ts,Egress_port,Delta_ts,SrcAddr,DstAddr,Version,SrcPort,DstPort,Link_ts,Pswitch_id]
    data_obj={'data':pkt_data,'offset':0}

    eth=header_extract(hdr_eth,data_obj)
    ipv4=header_extract(hdr_ipv4,data_obj)
    dstAddr1=ipv4['dstAddr1']['value']
    dstAddr2=ipv4['dstAddr2']['value']
    dstAddr3=ipv4['dstAddr3']['value']
    dstAddr4=ipv4['dstAddr4']['value']
    dstAddr=str(dstAddr1)+'.'+str(dstAddr2)+'.'+str(dstAddr3)+'.'+str(dstAddr4)
    
    srcAddr1=ipv4['srcAddr1']['value']
    srcAddr2=ipv4['srcAddr2']['value']
    srcAddr3=ipv4['srcAddr3']['value']
    srcAddr4=ipv4['srcAddr4']['value']
    srcAddr=str(srcAddr1)+'.'+str(srcAddr2)+'.'+str(srcAddr3)+'.'+str(srcAddr4)
    version=ipv4['protocol']['value']

    DstAddr.append(dstAddr)
    DstAddr.append(dstAddr)
    DstAddr.append(dstAddr)
    DstAddr.append(dstAddr)

    SrcAddr.append(srcAddr)
    SrcAddr.append(srcAddr)
    SrcAddr.append(srcAddr)
    SrcAddr.append(srcAddr)

    Version.append(version)
    Version.append(version)
    Version.append(version)
    Version.append(version)

    #vxlan_gpe=header_extract(hdr_vxlan_gpe,data_obj)
    #vxlan_gpe_int=header_extract(hdr_vxlan_gpe_int,data_obj)
 
    if eth['etherType']['value']!=0x0800:
        print "non ipv4"
	a=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    	header_display(a)    
        return
    if ipv4['protocol']['value']==0x11:
        print "protocal is udp"
	
	udp=header_extract(hdr_udp,data_obj)
        srcPort=udp['srcPort']['value']
        dstPort=udp['dstPort']['value']
        SrcPort.append(srcPort)
        SrcPort.append(srcPort)
        SrcPort.append(srcPort)
        SrcPort.append(srcPort)

        DstPort.append(dstPort)
        DstPort.append(dstPort)
        DstPort.append(dstPort)
        DstPort.append(dstPort)
	if udp['dstPort']['value']!=4790:
        	print"no int_header"
		a=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    		header_display(a) 
         	return
    if ipv4['protocol']['value']==0x06:
        print "protocal is tcp"
        
	tcp=header_extract(hdr_tcp,data_obj)
        srcPort=tcp['srcPort']['value']
        dstPort=tcp['int_dstPort']['value']
        SrcPort.append(srcPort)
        SrcPort.append(srcPort)
        SrcPort.append(srcPort)
        SrcPort.append(srcPort)
        DstPort.append(dstPort)
        DstPort.append(dstPort)
        DstPort.append(dstPort)
        DstPort.append(dstPort)
   	if tcp['int_dstPort']['value']!=4790:
        	print"no int_header"
	        a=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    	        header_display(a)   
         	return
    int_header=header_extract(hdr_int_header,data_obj)
    
    present_options=[]
    fields_mask=int_header['instruction_mask_0003']['value']<<4
    fields_mask|=int_header['instruction_mask_0407']['value']<<0
    
    options_in_order=[
        ("switch_id",hdr_int_switch_id),
        ("ingress_port",hdr_int_ingress_port),
        ("ingress_ts",hdr_int_ingress_ts),
        ("enq_depth",hdr_int_enq_depth),
        ("deq_timedelta",hdr_int_deq_timedelta),
        ("deq_depth",hdr_int_deq_depth),
	("egress_ts",hdr_int_egress_ts),
        ("egress_port",hdr_int_egress_port),
        ]
    
    for i in reversed(range(len(options_in_order))):
         if fields_mask &(1<<i):
         	present_options.append(options_in_order[len(options_in_order)-i-1])
    
    
    #
    ins_count=int_header['ins_cnt']['value']
    int_len=int_header['int_length']['value']
    opt_len=int_len-12#
    opt_sets=(opt_len/ins_count)/4
    
    hdr=None
    for opt_set in range(opt_sets):
        
        
        j=0
	pswitch_id=switch_id
        for option_name,option_header in present_options:
    	    hdr=header_extract(option_header,data_obj)
            header_print(hdr,"[%d]"%(opt_set)+ option_name,4)
	    
	    if j==0 : switch_id = hdr['switch_id']['value']
	    if j==1 : 
		ingress_port = hdr['ingress_port']['value']
		ingress_port_count = hdr['ingress_port_count']['value']
	    if j==2 : ingress_ts = hdr['ingress_ts']['value']
            if j==3 : enq_depth = hdr['enq_depth']['value']
            if j==4 : deq_timedelta = hdr['deq_timedelta']['value']
	    if j==5 : deq_depth = hdr['deq_depth']['value']
	    if j==6 : 
                
            	egress_ts = hdr['egress_ts']['value']
                link_ts=in_ts-egress_ts
		delta_ts = egress_ts - ingress_ts
                if(link_ts>=250000):
			n=n+1 
                in_ts= ingress_ts
	    if j==7 : 
		egress_port= hdr['egress_port']['value']
		egress_port_count= hdr['egress_port_count']['value']

            j+=1
	    
    	
	
	
	
	
	
	#print(switch_id)
        Switch_id.append(switch_id)
        Ingress_port.append(ingress_port)
	Ingress_port_count.append(ingress_port_count)
        Ingress_ts.append(ingress_ts)
        Enq_depth.append(enq_depth)
        Deq_timedelta.append(deq_timedelta)
        Deq_depth.append(deq_depth)
        Egress_ts.append(egress_ts)
        Egress_port.append(egress_port)
	Egress_port_count.append(egress_port_count)
        Delta_ts.append(delta_ts)
        Link_ts.append(link_ts)
	length=ipv4['totalLen']['value']+int_header['int_length']['value']+14
        Length.append(length)
        Pswitch_id.append(pswitch_id)
    
    Link_ts[0]=0
    Pswitch_id[0]=0
    g.labels(s='length',p=version).set(length)
    print(Ingress_port_count)
    print(Egress_port_count)
    g.labels(s='Version',p=version).set(version)
    g.labels(s='SrcPort',p=version).set(srcPort)
    g.labels(s='DstPort',p=version).set(dstPort)#five-tuple

    g.labels(s='Deq_timedelta1',p=version).set(Deq_timedelta[0])
    g.labels(s='Deq_timedelta2',p=version).set(Deq_timedelta[1])
    g.labels(s='Deq_timedelta3',p=version).set(Deq_timedelta[2])
    g.labels(s='Deq_timedelta4',p=version).set(Deq_timedelta[3])


    g.labels(s='Ingress_port_count1',p=version).set(Ingress_port_count[0])
    g.labels(s='Ingress_port_count2',p=version).set(Ingress_port_count[1])
    g.labels(s='Ingress_port_count3',p=version).set(Ingress_port_count[2])
    g.labels(s='Ingress_port_count4',p=version).set(Ingress_port_count[3])

    g.labels(s='Egress_port_count1',p=version).set(Egress_port_count[0])
    g.labels(s='Egress_port_count2',p=version).set(Egress_port_count[1])
    g.labels(s='Egress_port_count3',p=version).set(Egress_port_count[2])
    g.labels(s='Egress_port_count4',p=version).set(Egress_port_count[3])

    g.labels(s='Link_ts1',p=version).set(0)
    g.labels(s='Link_ts2',p=version).set(Link_ts[1])
    g.labels(s='Link_ts3',p=version).set(Link_ts[2])
    g.labels(s='Link_ts4',p=version).set(Link_ts[3])
  
    g.labels(s='Delta_ts1',p=version).set(Delta_ts[0])
    g.labels(s='Delta_ts2',p=version).set(Delta_ts[1])
    g.labels(s='Delta_ts3',p=version).set(Delta_ts[2])
    g.labels(s='Delta_ts4',p=version).set(Delta_ts[3])

    g.labels(s='Deq_depth1',p=version).set(Deq_depth[0])
    g.labels(s='Deq_depth2',p=version).set(Deq_depth[1])
    g.labels(s='Deq_depth3',p=version).set(Deq_depth[2])
    g.labels(s='Deq_depth4',p=version).set(Deq_depth[3])
    
    #print(len(a[0]),len(a[1]),len(a[2]),len(a[3]),len(a[4]),len(a[5]),len(a[6]),len(a[7]),len(a[8]),len(a[9]),len(a[10]),len(a[11]),len(a[12]),len(a[13]),len(a[14]),len(a[14]))
    header_display(a)     
    
#    if hdr:
#        if hdr['bos']['value']==0:
#            print "         invalid BOS"

            
#
if len(sys.argv)!=2:
    print "expect either interface or pcap file as argument"
    sys.exit(1)

pkts=None
try:
    capfile=open(sys.argv[1],'rb')
    capdata=savefile.load_savefile(capfile)
    pkts=[]
    for pkt_no in range(len(capdata.packets)):   #
        pkts.append(str(capdata.packets[pkts_no]))
except:
    pass

pktno=0
#
if pkts!=None:
    for pkt_data in pkts:
        print "packet #%d" %pktno
        process_int_pkt(pkt_data)
        pktno+=1
else:
    try:
        p=pcapy.open_live(sys.argv[1],1500,1,0)
    except:
        print "invalid interface or pcap file provided"
        sys.exit(1)
        
    while True:
        try:
            (header,packet)=p.next()
        except:
            continue

        print "packet #%d" %pktno
	g.labels(s='Packet_number',p=1).set(pktno)
	global pktno
        Pktno=[]
        Pktno.append(pktno)
        Pktno.append(pktno)
        Pktno.append(pktno)
        Pktno.append(pktno)
        process_int_pkt(str(packet))
        if(n>=50000):
		table.change()
        	n=0
	pktno+=1
            
    



