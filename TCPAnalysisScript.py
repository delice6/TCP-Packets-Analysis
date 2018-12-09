import csv
import nltk
from nltk.tokenize import MWETokenizer
from nltk.tokenize import RegexpTokenizer

"""
This function extracts information from csv file and saves it in lists
"""
def breaking_up_csv_file(csv_reader): 
	Source = []
	Destination = []
	Info = []
	for row in csv_reader:
			if(row[4] != 'ARP'):
				Source.append(row[2])
				Destination.append(row[3])
				Info.append(row[6])
	return Source, Destination, Info

"""
This function breaks up the info colunm into strings that is easy to sort through
"""	
def breaking_up_info_colunm(Info): 
	column = 0
	tokenizer = RegexpTokenizer('\w+' , gaps=False)
	while column < len(Info):
			Info[column] = tokenizer.tokenize(Info[column])
			column += 1
	return Info

"""
This function calculates the number of client machines on the network
"""	
def number_of_clients(numberofclients): 
	index = 0
	numberOfClients = []
	while index < len(numberofclients):
		if(numberofclients[index] != '150.100.0.2'):
			numberOfClients.append(numberofclients[index])
		index += 1
	numberOfClients = list(set(numberOfClients))
	return numberOfClients

"""
This function calculates the number of control packets
"""	
def ctrl_Packets(client_machine, source, destination, info): 
	indx = 0
	ctrl_Packets = []
	while indx < len(client_machine):
		number_of_ctrl_packets = 0
		inner_indx = 0
		while inner_indx < len(source):
			if(client_machine[indx] == source[inner_indx] and destination[inner_indx] == '150.100.0.2'):
				if('SYN' in info[inner_indx] or 'FIN' in info[inner_indx]):
					number_of_ctrl_packets += 1
			inner_indx += 1
		ctrl_Packets.append(number_of_ctrl_packets)
		indx += 1
	
	return ctrl_Packets

"""
This function calculates the number of data packets
"""	
def data_Packets(client_machine, source, destination, info): 
	indx = 0
	data_Packets = []
	while indx < len(client_machine):
		number_of_data_packets = 0
		inner_indx = 0
		while inner_indx < len(source):
			if(client_machine[indx] == source[inner_indx] and destination[inner_indx] == '150.100.0.2'):
				indexOfLen = info[inner_indx].index('Len')
				if('SYN' not in info[inner_indx] and 'FIN' not in info[inner_indx]):
					if('ACK' in info[inner_indx] and info[inner_indx][indexOfLen+1] != '0'):
						number_of_data_packets += 1
			inner_indx += 1
		data_Packets.append(number_of_data_packets)
		indx += 1
	return data_Packets

"""
This function calculates the number of new acks
"""	
def new_Acks(client_machine, source, destination, info): 
	indx = 0
	new_Acks = []
	while indx < len(client_machine):
		number_of_new_acks = 0
		previousAck = 0
		currentAck = 0
		inner_indx = 0
		while inner_indx < len(source):
			if(client_machine[indx] == source[inner_indx] and destination[inner_indx] == '150.100.0.2'):
				if('Ack' in info[inner_indx]):
					indexOfAck = info[inner_indx].index('Ack')
					currentAck = int(float(info[inner_indx][indexOfAck + 1]))
					if(currentAck != previousAck):
						number_of_new_acks += 1
					previousAck = currentAck
			inner_indx += 1
		new_Acks.append(number_of_new_acks)
		indx += 1
	return new_Acks

"""
This function calculates the number of redundant acks
"""	
def redundant_Acks(client_machine, source, destination, info): 
	indx = 0
	redundant_Acks = []
	
	while indx < len(client_machine):
		number_of_redundant_acks = 0
		previousAck = 0
		currentAck = 0
		inner_indx = 0
		while inner_indx < len(source):
			if(client_machine[indx] == source[inner_indx] and destination[inner_indx] == '150.100.0.2'):
				if('Ack' in info[inner_indx]):
					indexOfAck = info[inner_indx].index('Ack')
					currentAck = int(float(info[inner_indx][indexOfAck + 1]))
					if(currentAck == previousAck):
						number_of_redundant_acks += 1
					previousAck = currentAck
			inner_indx += 1
		redundant_Acks.append(number_of_redundant_acks)
		indx += 1
	return redundant_Acks
	
"""
This function calculates the number of dedicated acks
"""	
def dedicated_Acks(client_machine, source, destination, info): 
	dedicated_Acks = []
	indx = 0
	while indx < len(client_machine):
		number_of_dedicated_Acks = 0
		inner_indx = 0
		while inner_indx < len(source):
			if(client_machine[indx] == source[inner_indx] and destination[inner_indx] == '150.100.0.2'):
				indexOfLen = info[inner_indx].index('Len')
				if('SYN' not in info[inner_indx] and 'FIN' not in info[inner_indx] and 'ACK' in info[inner_indx] and info[inner_indx][indexOfLen+1] == '0'):
					number_of_dedicated_Acks += 1
			inner_indx += 1
		dedicated_Acks.append(number_of_dedicated_Acks)
		indx += 1
	return dedicated_Acks

"""
This function calculates the number of bad acks
"""	
def bad_Acks(client_machine, source, destination, info): #This function calculates the number of bad acks
	bad_Acks = []
	indx = 0
	while indx < len(client_machine):
		numberOfBadAcks = 0
		inner_indx1 = 0
		#This outer loop goes through the destination to calculate the expected Ack
		while inner_indx1 < len(destination):
			currentSequence = 0
			currentLength = 0
			expectedAck = 0
			actualAck = 0
			if(client_machine[indx] == destination[inner_indx1] and source[inner_indx1] == '150.100.0.2'):
				if('Seq' in info[inner_indx1]):
					indexOfSeq = info[inner_indx1].index('Seq')
					currentSequence = int(float(info[inner_indx1][indexOfSeq+1]))
				if('Len' in info[inner_indx1]):
					indexOfLen = info[inner_indx1].index('Len')
					currentLength = int(float(info[inner_indx1][indexOfLen+1]))
				if('SYN' in info[inner_indx1] or 'FIN' in info[inner_indx1]):
					expectedAck = currentSequence + currentLength + 1
				else:
					expectedAck = currentSequence + currentLength
				
				#Loop through source to see if it is the expected Ack being sent
				inner_indx2 = inner_indx1 + 1
				while inner_indx2 < len(source):
					if(destination[inner_indx2] == '150.100.0.2' and source[inner_indx2] == client_machine[indx]):
						if('Ack' in info[inner_indx2]):
							indexOfAck = info[inner_indx2].index('Ack')
							currentAck = int(float(info[inner_indx2][indexOfAck + 1]))
							if(currentAck < expectedAck):
								numberOfBadAcks += 1
							break
					inner_indx2 += 1
			inner_indx1 += 1
		bad_Acks.append(numberOfBadAcks)
		indx+= 1
	return bad_Acks
	
	
def main():

	with open('ServerTraffic-F2018.csv') as proj3_output:
		csv_reader = csv.reader(proj3_output, delimiter=',')  #Reading the file
		
		
		Source = []
		Destination = []
		info = []
		numberOfClients = []
		final_Output = [["client_Machine", "ctrl_Packets", "data_Packets", "new_Acks", "redundant_Acks", "dedicated_Acks", "bad_Acks"], ["client_Machine", "ctrl_Packets", "data_Packets", "new_Acks", "redundant_Acks", "dedicated_Acks", "bad_Acks"]]
		
		next(csv_reader, None)

		(Source, Destination, info) = breaking_up_csv_file(csv_reader)
		info = breaking_up_info_colunm(info)
		numberOfClients = number_of_clients(Source)
		
		"""
		Calculating the Client to Server Traffic
		"""
		
		
		ctrlPackets_clientToServer = ctrl_Packets(numberOfClients, Source, Destination, info)
		dataPackets_clientToServer = data_Packets(numberOfClients, Source, Destination, info)
		newAcks_clientToServer = new_Acks(numberOfClients, Source, Destination, info)
		redundantAcks_clientToServer = redundant_Acks(numberOfClients, Source, Destination, info)
		dedicatedAcks_clientToServer = dedicated_Acks(numberOfClients, Source, Destination, info)
		badAcks_clientToServer = bad_Acks(numberOfClients, Source, Destination, info)
		
		"""
		Calculating the Server to Client Traffic
		"""
		
		ctrlPackets_serverToClient = ctrl_Packets(numberOfClients, Destination, Source, info)
		dataPackets_serverToClient = data_Packets(numberOfClients, Destination, Source, info)
		newAcks_serverToClient = new_Acks(numberOfClients, Destination, Source, info)
		redundantAcks_serverToClient = redundant_Acks(numberOfClients, Destination, Source, info)
		dedicatedAcks_serverToClient = dedicated_Acks(numberOfClients, Destination, Source, info)
		badAcks_serverToClient = bad_Acks(numberOfClients, Destination, Source, info)
		
		"""
		Writing the output to a text file
		"""
		
		indx = 0
		outputString = ""
		while indx < len(numberOfClients):
			outputString += ("> " + str(numberOfClients[indx]) + " <\n Client to Server Traffic: \n" + 
			"  #Data Pckt: " + str(dataPackets_clientToServer[indx]) + "," + 
			" #Ctrl Pckt: " + str(ctrlPackets_clientToServer[indx]) + "," +
			" #New Ack: " + str(newAcks_clientToServer[indx]) + "," +
			" #Redn Ack: " + str(redundantAcks_clientToServer[indx]) + "," +
			" #Dedicated Ack: " + str(dedicatedAcks_clientToServer[indx]) + "," +
			" #Bad Ack: " + str(badAcks_clientToServer[indx]) + " \n Server to Client Traffic: \n" +
			"  #Data Pckt: " + str(dataPackets_serverToClient[indx]) + "," +
			" #Ctrl Pckt: " + str(ctrlPackets_serverToClient[indx]) + "," +
			" #New Ack: " + str(newAcks_serverToClient[indx]) + "," +
			" #Redn Ack: " + str(redundantAcks_serverToClient[indx]) + "," +
			" #Dedicated Ack: " + str(dedicatedAcks_serverToClient[indx]) + "," +
			" #Bad Ack: " + str(badAcks_serverToClient[indx]) + "\n\n"
			)
			indx += 1
		print(outputString)	
		
		text_file = open("ProgramOutput.txt", "w")
		text_file.write(outputString)
		text_file.close()
		
		
if __name__ == "__main__":
	main()
	
