#!/usr/bin/python
import os,sys
import collections
import pyeda.inter as pyedaitr
import itertools as itr


class Logic_decryptor(object):
	def __init__(self,file_enc,file_org):
		self.gate=''				#gate
		self.ins=[]					#inputs
		self.out=''					#output
		self.netlist={}				#dictionary of netlist
		self.outputs=[]				#output list
		self.inputs=[]				#input list
		self.truth_tbl_output={}	#truth values for each output wires
		self.IpOp_parse_done=0
		#------------------temp variables--------------#
		self.Ip=pyedaitr.exprvars('Ip',1)
		self.KeyIp=pyedaitr.exprvars('KeyIp',1)
		#------------------encA variables--------------#
		self.IpE=pyedaitr.exprvars('Ip',1)
		self.KeyIpE=pyedaitr.exprvars('KeyIp',1)
		# #------------------encB variables--------------#
		# self.IpB=pyedaitr.exprvars('Ip',1)
		# self.KeyIpB=pyedaitr.exprvars('KeyIp',1)
		#------------------orgN variables--------------#
		self.IpO=pyedaitr.exprvars('Ip',1)

		self.y1=None
		self.y2=None
		self.xd=None
		self.yd=None


		self.keys=()
		self.noskeys=0
		self.nosips=0

		self.do_mitter_net(file_enc)
		self.do_original_net(file_org)
		self.eliminate_key()

	def do_mitter_net(self,file_enc):
		self.netlist.clear()
		self.outputs=[]				#output list
		self.inputs=[]				#input list
		with open(dirConst+'/'+file_enc) as f:
			for line in f:
				self.parser(line)
		#map all gates to output line
		tmp_lst=[]
		for i,item in enumerate(self.outputs):
			if(self.netlist.get(item,None) is not None):
				#if the wire is coming from other gate
				tmp_lst.append(self.netlist.get(item,None))
		self.y1=pyedaitr.farray([x for x in tmp_lst])
		# print("-------------------------netlist-------------------------")
		# print(self.netlist)
		# print("-------------------------inputs -------------------------")
		# print(self.inputs)
		# print("-------------------------output -------------------------")
		self.y2=self.y1
		self.IpE=self.Ip
		self.KeyIpE=self.KeyIp
		self.noskeys=self.get_nokeys()
		# print(self.y1)
		# print(self.IpE,self.KeyIpE)

	def do_original_net(self,file_org):
		self.netlist.clear()
		self.outputs=[]				#output list
		self.inputs=[]				#input list
		with open(dirConst+'/'+file_org) as f:
			for line in f:
				self.parser(line)
		#map all gates to output line
		tmp_lst=[]
		for i,item in enumerate(self.outputs):
			if(self.netlist.get(item,None) is not None):
				#if the wire is coming from other gate
				tmp_lst.append(self.netlist.get(item,None))
		self.yd=pyedaitr.farray([x for x in tmp_lst])
		self.nosips=len(self.inputs)
		# print("-------------------------netlist-------------------------")
		# print(self.netlist)
		# print("-------------------------inputs -------------------------")
		# print(self.inputs)
		# print("-------------------------output -------------------------")
		self.IpO=self.Ip
		# print(self.yd)
		# print(self.IpO)

	def eliminate_key(self):
		diff = lambda l1,l2: [x for x in l1 if x != l2]
		tmp_key_lst=[]
		for i in range(0,2**self.noskeys):
			tmp_key_lst.append(i) 

		for ipVector in range(0,2**self.nosips):
			self.keys=tuple(itr.combinations_with_replacement(tuple(tmp_key_lst),2))
			DIP_key_lst=[]
			ip_bin=bin(ipVector)[2:].zfill(self.nosips)
			for key1, key2 in self.keys:
				key_bin=bin(key1)[2:].zfill(self.noskeys)
				yy1=self.y1.vrestrict({self.IpE: ip_bin,self.KeyIpE: key_bin}).to_uint()
				key_bin=bin(key2)[2:].zfill(self.noskeys)
				yy2=self.y1.vrestrict({self.IpE: ip_bin,self.KeyIpE: key_bin}).to_uint()

				if(yy1 != yy2):
					#Finding the DIP's
					DIP_key_lst.append((key1,key2))
			print("------------------- List of key for DIP : %d -------------------" %ipVector)
			print("Round",ipVector,DIP_key_lst)
			print("----------------------------------------------------------------")
			if(len(DIP_key_lst)!=0):
				for key1,key2 in DIP_key_lst:
					key_bin=bin(key1)[2:].zfill(self.noskeys)
					yy1=self.y1.vrestrict({self.IpE: ip_bin,self.KeyIpE: key_bin}).to_uint()
					key_bin=bin(key2)[2:].zfill(self.noskeys)
					yy2=self.y1.vrestrict({self.IpE: ip_bin,self.KeyIpE: key_bin}).to_uint()
					y_org=self.yd.vrestrict({self.Ip: ip_bin}).to_uint()
					if(y_org != yy1):
						if(key1 in tmp_key_lst):
							tmp_key_lst.remove(key1)
							print("Key elminated",key1)
					if(y_org !=yy2):
						if(key2 in tmp_key_lst):
							tmp_key_lst.remove(key2)
							print("Key elminated",key2)
			if(len(tmp_key_lst)==1):
				print("****************************************************")
				print("keyfound:",tmp_key_lst[0])
				print("****************************************************")
				self.keys=tmp_key_lst[0]
				break



	def init_pins(self):
		self.IpOp_parse_done=1
		Nos_keyIps=self.get_nokeys()



		return([pyedaitr.exprvars('Ip',len(self.inputs)-Nos_keyIps),pyedaitr.exprvars('Op',len(self.outputs)),pyedaitr.exprvars('KeyIp',Nos_keyIps)])

	def get_nokeys(self):
		Nos_keyIps=0
		for ips in self.inputs:
			if("key" in ips):
				Nos_keyIps+=1
		return Nos_keyIps

	def parser(self,node,type=None):

		if('#' in node):
			return
		elif('=' in node):
			#parsing gate lines
			if(self.IpOp_parse_done == 0):
				# The input and output pins parse is complete
				retvals=self.init_pins()
				self.Ip=retvals[0]
				self.Op=retvals[1]
				self.KeyIp=retvals[2]
				# print(self.Ip,self.Op,self.KeyIp)
				self.map_wiretopin()
			
			self.out	,self.gate	= node.replace(" ","").split("=")
			self.gate	,self.ins   = self.gate.split("(")
			self.ins				= self.ins.replace(")\n","")
			self.ins				= self.ins.split(",")
			# print(self.out,self.gate,self.ins)
			self.getnetlist()
		else:
			#parsing input and output lines
			self.IpOp_parse_done=0
			self.out=''
			self.gate	,self.ins	= node.replace(" ","").split("(")
			self.ins				= self.ins.replace(")\n","")
			# print(self.out,self.gate,self.ins)
			self.getnetlist()

	def getnetlist(self):
		#adds node to dictionary with every iteration
		if(self.gate.lower() == 'input'):
			self.inputs.append(self.ins)
		elif(self.gate.lower() == 'output'):
			self.outputs.append(self.ins)
		else:
			tmp_ins=[]
			for i,item in enumerate(self.ins):
				if(self.netlist.get(item,None) is not None):
					#if the wire is coming from other gate
					self.ins[i]=self.netlist.get(item,None)

		if(self.gate.lower() == 'nand'):
			self.netlist[self.out]= pyedaitr.Nand(*self.ins)
		elif(self.gate.lower() == 'and'):
			self.netlist[self.out]= pyedaitr.And(*self.ins)
		elif(self.gate.lower() == 'or'):
			self.netlist[self.out]= pyedaitr.Or(*self.ins)
		elif(self.gate.lower() == 'nor'):
			self.netlist[self.out]= pyedaitr.Nor(*self.ins)
		elif(self.gate.lower() == 'xnor'):
			self.netlist[self.out]= pyedaitr.Xnor(*self.ins)
		elif(self.gate.lower() == 'xor'):
			self.netlist[self.out]= pyedaitr.Xor(*self.ins)
		elif(self.gate.lower() == 'not'):
			self.netlist[self.out]= pyedaitr.Not(*self.ins)
		elif(self.gate.lower() == 'buf'):
			try:
				self.netlist[self.out]= pyedaitr.exprvar(str(self.ins[0]))
			except ValueError:
				self.netlist[self.out]= self.ins

	def map_wiretopin(self):
			#maps wire to pins ex:G123-->Ip[0]
		ip_no=0
		key_no=0
		out_no=0
		for ips in self.inputs:
			if("key" in ips):
				self.netlist[ips]=self.KeyIp[key_no]
				key_no+=1
			else:
				self.netlist[ips]=self.Ip[ip_no]
				ip_no+=1

	def printval(self):
		try:
			print("------------------------ netlist ------------------------")
			print(self.netlist)
			print("------------------------- output ------------------------")
			print(self.outputs)
			print("------------------------- inputs ------------------------")
			print(self.inputs)
			print("------------------------ Key Found ----------------------")
			print(self.keys)
		except AttributeError:
			return


if __name__ == '__main__':
	dirConst= os.getcwd()
	logic_line=Logic_decryptor('sample_enc.bench','sample.bench')

