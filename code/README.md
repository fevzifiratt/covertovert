# Chosen Covert Channel Type: Covert Storage Channel that exploits Protocol Field Manipulation using ECE Flag field in TCP [Code: CSC-PSV-TCP-ECE] 

A Covert Storage Channel is a method of transmitting information secretly by exploiting an existing communication protocol's fields in ways they were not intended to be used. In our homework, this technique involves the ECE (Explicit Congestion Notification Echo) flag in the TCP header, and it manipulates this field to send hidden data between two parties. Instead of directly putting the message to the payload, we set the ECE bit by using a custom encryption technique, and send that message bit by bit.


For instance, if we have a message having a length of 16 bytes, we need to send 128 packets where the ECE bit contains the encrypted bit of the message.


In this homework, for sender, we create a random binary message and convert it into an encrypted form using our encryption algorithm. For each bit, a separate TCP packet is sent to the specified target IP address and port. We The message sent is stored in the log files: "sender.log" for sender, and "receiver.log" for the receiver.


# Encryption Algorithm


Our encryption algorithm is as follows:
- For a binary message X, assign the most significant bit (MSB) of the encrypted message Y to the complement of the MSB of X.
- For the remaining bits:
	If the previous bit of X is equal to the current bit of X
		Take the complement of the previous bit of Y as the current bit of Y
	Else
		Set the current bit of Y same as the previous bit of Y.
		
		
At the receiver side, we sniff TCP packets arriving to the receiver. The sniff function is used for this purpose, and all IPs and ports are explicitly specified as filters in the sniff function. This ensures that the receiver only captures packets coming from the sender, preventing the reception of irrelevant messages unrelated to our covert channel. 


Since we send our message bit by bit, the receiver has to wait 8 packets to decrypt a character. Our decryption algorithm is the inverse of our encryption algorithm. 


# Link Capacity


We followed the steps in the homework PDF to measure link capacity. We had the following output:
Link capacity: 44.16366498157266 bits/sec


# Parameters


For "send" function, we have "reciever\_ip, receiver\_port, sender\_port, log\_file\_name, max\_length, min\_length" parameters. for "max\_length and min\_length", you can give values between 0 and any length you want. Preferably, do not exceed 100.


For"receive" function, we have "sender\_ip, reciever\_ip, sender\_port, receiver\_port, log\_file\_name" parameters. 

