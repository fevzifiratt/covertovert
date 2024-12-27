from CovertChannelBase import CovertChannelBase
from scapy.all import IP, TCP, sniff
import time


class MyCovertChannel(CovertChannelBase):
    def _init_(self):
        pass

    def encrypt(self, counter, message_prev, encrypted_prev, ch):
        ### The first bit
        ch_numeric = eval(ch)
        if counter == 0:
            if not ch_numeric:
                flag = 1
                encrypted_prev = 1
            else:
                flag = 0
                encrypted_prev = 0
        ### Other bits
        else:
            if ch_numeric == message_prev:
                if not encrypted_prev:
                    flag = 1
                else:
                    flag = 0
                encrypted_prev = not encrypted_prev
            else:
                if encrypted_prev:
                    flag = 1
                else:
                    flag = 0

        message_prev = ch_numeric
        return flag, message_prev, encrypted_prev
    
    def decrypt(self, counter, encrypted_prev, decrypted_prev, ch):
        # first element. take complement
        if counter == 0:
            if ch == '0':
                flag = 1
                decrypted_prev = '1'
            else:
                flag = 0
                decrypted_prev = '0'
        else:
            # if encrypted same, different prev_decrypted
            if ch == encrypted_prev:
                if decrypted_prev == '0':
                    flag = 1
                    decrypted_prev = '1'
                else:
                    flag = 0
                    decrypted_prev = '0'
            # if encrypted different, same prev_decrypted
            else:
                if decrypted_prev == '0':
                    flag = 0
                else:
                    flag = 1

        encrypted_prev = ch

        return flag, encrypted_prev, decrypted_prev

    def send(self, receiver_ip, receiver_port, sender_port, log_file_name, min_length, max_length):
        """
        In this function, we generate a random binary message and convert it into an encrypted form using our encryption algorithm.
        Then, each bit of the encrypted message is stored in the ECE field of the TCP packet's header. For each bit, a separate 
        TCP packet is sent to the specified target IP address and port. We also measure the capacity of the link and the message sent 
        is stored in a log file.

        
        Our encryption algorithm is as follows:
        - For a binary message X, assign the most significant bit (MSB) of the encrypted message Y to the complement of the MSB of X.
        - For the remaining bits:
            If the previous bit of X is equal to the current bit of X
                Take the complement of the previous bit of Y as the current bit of Y
            Else
                Set the current bit of Y same as the previous bit of Y.

        Link capacity: 44.16366498157266 bits/sec
        
        """

        binary_message = self.generate_random_binary_message_with_logging(log_file_name, min_length=min_length, max_length=max_length)

        ip_layer = IP(dst=receiver_ip)
        tcp_layer = TCP(dport=receiver_port, sport=sender_port)

        payload = self.generate_random_message()

        counter = 0
        message_prev = 0
        encrypted_prev = 0

        t_initial = 0
        t_end = 0
        for ch in binary_message:
            flag, message_prev, encrypted_prev = self.encrypt(counter, message_prev, encrypted_prev, ch)

            if flag:
                tcp_layer.flags = "E"
            else:
                tcp_layer.flags = ""

            packet = ip_layer / tcp_layer / payload
            if(counter == 0):
                t_initial = time.time()

            CovertChannelBase.send(self, packet)

            if(counter == len(binary_message)-1):
                t_end = time.time()
            # time.sleep(stime)
            # ret = sniff(filter=f"src host {self.receiver_ip}", count=1)
            # print(f"Packet sent to {self.receiver_ip}:{self.receiver_port}")
            counter += 1
        
        # the print function for capacity is below
        # print(f"Link capacity: {128/(t_end - t_initial)} bits/sec")

    def receive(self, sender_ip, receiver_ip, sender_port, receiver_port, log_file_name):
        """
        In this function, we sniff TCP packets arriving from the sender to the receiver. The sniff function is used for this purpose, 
        and all IPs and ports are explicitly specified as filters in the sniff function. This ensures that the receiver 
        only captures packets coming from the sender, preventing the reception of irrelevant messages unrelated to our 
        covert channel. Since each TCP packet represents a bit and each character consists of 8 bits, we read 8 packets and 
        interpret these bits to retrieve the decrypted message. Our decryption algorithm is the inverse of our encryption algorithm.
        """
        
        current_message = ""
        main_message = ""
        current_length = 0

        def stop_filter(packet):
            nonlocal current_message, main_message, current_length
            current_message += str(int(packet['TCP'].flags & 0x40) >> 6)
            current_length += 1
            if(current_length == 8):
                decrypted_message = ""
                counter = 0
                encrypted_prev = '0'
                decrypted_prev = '0'
                for ch in current_message:
                    flag, encrypted_prev, decrypted_prev = self.decrypt(counter, encrypted_prev, decrypted_prev, ch)
                    if flag:
                        decrypted_message += '1'
                    else:
                        decrypted_message += '0'

                    counter += 1

                decrypted_message_new = CovertChannelBase.convert_eight_bits_to_character(self, decrypted_message)
                main_message += decrypted_message_new
                
                current_message = ""
                current_length = 0

                if(decrypted_message_new == "."):
                    return True
                
            return False
        
        # Sniff packets on the default interface
        print("Receiver is sniffing packets...")

        sniff(filter=f"tcp and src host {sender_ip} and dst host {receiver_ip}\
              and src port {sender_port} and dst port {receiver_port}", stop_filter=stop_filter)
                
        self.log_message(main_message, log_file_name)