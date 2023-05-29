#!/usr/bin/env python3

import binascii
import hashlib
import logging
import math
import optparse
import os
import os.path
import shutil
import socket
import sqlite3
import struct
import sys
import tempfile
import time
import traceback

import TabBits

TEMP_PATH="/mnt/void/recv/.~bftp/"

PACKET_SIZE = 65500  # maximum packet size
MAX_FILENAME_LEN = 1024  # maximum filename size

# Header of BFTP packet (format v5):
# (see struct help for codes)
# - packet type: uchar=B
# - length of file name (+ path): uchar=B
# - length of file data in packet: uint16=H
# - offset, position of data in file: u long long=Q
# - session number: uint32=I
# - packet number in session: uint32=I
# - file packet number: uint32=I
# - number of packets for file: uint32=I
# - file length (in bytes): u long long=Q
# - file date (in seconds since epoch): float=f
# - CRC32 of file: uint32=I
# (followed by the name of the file, then the data)
FORMAT_HEADER = "BBHQIIIIQfI"
LENGTH_HEADER = struct.calcsize(FORMAT_HEADER)

# Types of packets:
PACKET_FILE = 0
PACKET_DIRECTORY = 1

global options
options = None

global files
files = {}


class File:
    def __init__(self, packet):
        self.file_name = packet.file_name
        self.file_mtime = packet.file_mtime
        self.file_size = packet.file_size
        self.num_total_file_packets = packet.num_total_file_packets

        self.file_dest_path = PATH_DEST + "/" + self.file_name
        self.temp_file = tempfile.NamedTemporaryFile(prefix='BFTP_',dir=TEMP_PATH,delete=False)
        self.packets_received = TabBits.TabBits(self.num_total_file_packets)

        self.terminated = False
        self.crc32 = packet.crc32  # file crc32

    def cancel_download(self):
        if not self.temp_file.closed:
            self.temp_file.close()

    def copy_to_dest(self, log_path):
        dest_dir = os.path.dirname(self.file_dest_path)
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)
        elif not os.path.isdir(dest_dir):
            os.remove(dest_dir)
            os.makedirs(dest_dir)

        # Copy but without checking crc32 (bad?)
        self.temp_file.close()
        shutil.move(self.temp_file.name, self.file_dest_path)
        print('Done')
        os.utime(self.file_dest_path, (self.file_mtime, self.file_mtime))
        print('')

        # Copy after validating crc32
        #self.temp_file.seek(0)
        #f_dest = open(self.file_dest_path, 'wb')
        #buffer = self.temp_file.read(16384)
        #crc32 = binascii.crc32(buffer)
        #while len(buffer) != 0:
        #    f_dest.write(buffer)
        #    buffer = self.temp_file.read(16384)
        #    crc32 = binascii.crc32(buffer, crc32)
        #f_dest.close()

        #if os.path.getsize(self.file_dest_path) != self.file_size:
        #    os.rename(self.file_dest_path, self.file_dest_path + ".ERRORSIZE")
        #    logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%Y/%m/%d %I:%M:%S %p',
        #                        filename=os.path.join(log_path, "bftp_errors.log"))
        #    logging.warning("File has invalid size: %s" % self.file_name)
        #    logging.shutdown()
        #    print('WARNING: Invalid file size "%s"' % self.file_name)
        #if self.crc32 != crc32:
        #    os.rename(self.file_dest_path, self.file_dest_path + ".ERRORCRC32")
        #    logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%Y/%m/%d %I:%M:%S %p',
        #                        filename=os.path.join(log_path, "bftp_errors.log"))
        #    logging.warning("File has invalid CRC32: %s" % self.file_name)
        #    logging.shutdown()
        #    print('WARNING: Invalid CRC32 "%s"' % self.file_name)
        #if self.crc32 == crc32 and os.path.getsize(self.file_dest_path) == self.file_size:
        #    print('Done')
        #    os.utime(self.file_dest_path, (self.file_mtime, self.file_mtime))
        #print('')
        #self.temp_file.close()
        #os.unlink(self.temp_file.name)


    def process_packet(self, packet, log_path):
        if not self.packets_received.get(packet.num_current_file_packet):
            self.temp_file.seek(packet.offset)
            self.temp_file.write(packet.data)
            self.packets_received.set(packet.num_current_file_packet, True)

            # generate progress bar
            progress = int(100 * self.packets_received.num_bits_set / self.num_total_file_packets)
            progress_str = list("[" + " " * 33 + "]")

            # add the bars
            bar_blocks = int(progress / 3) + 1
            for i in range(1, bar_blocks):
                progress_str[i] = "-"
            progress_str[bar_blocks] = ">"
            progress_str[34] = "]"

            # add the percentage number
            percent_str = str(progress) + "%"
            str_index = 16
            for c in percent_str:
                progress_str[str_index] = c
                str_index = str_index + 1

            print("".join(progress_str), end='\r')

            if self.packets_received.num_bits_set == self.num_total_file_packets:
                print('')
                self.copy_to_dest(log_path)
                self.terminated = True
                del files[self.file_name]


class Packet:
    def __init__(self):
        self.packet_type = PACKET_FILE
        self.name_length = 0
        self.data_size = 0
        self.offset = 0
        self.num_session = -1
        self.num_current_session_packet = -1
        self.num_current_file_packet = 0
        self.num_total_file_packets = 0
        self.file_size = 0
        self.file_mtime = 0

        self.file_name = ""
        self.data = ""
        self.current_file = ""

    def decoder(self, packet, log_path):
        header = packet[0:LENGTH_HEADER]
        (
            self.packet_type,
            self.name_length,
            self.data_size,
            self.offset,
            self.num_session,
            self.num_current_session_packet,
            self.num_current_file_packet,
            self.num_total_file_packets,
            self.file_size,
            self.file_mtime,
            self.crc32
        ) = struct.unpack(FORMAT_HEADER, header)

        if self.packet_type not in [PACKET_FILE, PACKET_DIRECTORY]:
            raise ValueError('Invalid packet type')
        if self.name_length > MAX_FILENAME_LEN:
            raise ValueError('Filename length too long')
        if self.offset + self.data_size > self.file_size:
            raise ValueError('Invalid file offset')

        self.file_name = packet[LENGTH_HEADER: LENGTH_HEADER + self.name_length]
        self.file_name = os.path.normpath(self.file_name)
        self.file_name = self.file_name.decode('utf-8')

        total_header_len = LENGTH_HEADER + self.name_length
        if self.data_size != len(packet) - total_header_len:
            raise ValueError('Incorrect data size')

        self.data = packet[total_header_len:len(packet)]

        if self.packet_type == PACKET_FILE:
            # Check if the previous file completed or not
            if self.current_file != "" and self.current_file != self.file_name:
                try:
                    f = files[self.current_file]
                    if not f.terminated:
                        # Previous file did not complete. Probably had some packet loss.
                        print('')
                        print('WARNING: "%s" did not complete' % self.current_file)
                        print('')

                        # Write to error log
                        logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%Y/%m/%d %I:%M:%S %p',
                                            filename=os.path.join(log_path, "bftp_errors.log"))
                        logging.warning("File did not complete: %s" % self.current_file)
                        logging.shutdown()
                    else:
                        raise KeyError
                except KeyError:
                    # Everything is OK. Previous file completed.
                    pass

            if self.file_name in files:
                f = files[self.file_name]
                if f.file_mtime != self.file_mtime \
                        or f.file_size != self.file_size \
                        or f.crc32 != self.crc32:
                    f.cancel_download()
                    del files[self.file_name]
                    self.new_file(log_path)
                else:
                    f.process_packet(self, log_path)
            else:
                dest_file = PATH_DEST + "/" + self.file_name
                if not os.path.exists(dest_file):
                    self.new_file(log_path)
                else:
                    # to prevent it spamming the "did not complete" error
                    if self.current_file != self.file_name:
                        print('WARNING: Ignoring existing file "%s"' % self.file_name)
                        print('')
                        self.current_file = self.file_name

        elif self.packet_type == PACKET_DIRECTORY:
            dest_dir = PATH_DEST + "/" + self.file_name
            if not os.path.exists(dest_dir):
                print('Received empty directory "%s"' % self.file_name)
                print('')
                os.makedirs(dest_dir)
            elif not os.path.isdir(dest_dir):
                print('Received empty directory "%s"' % self.file_name)
                print('')
                os.remove(dest_dir)
                os.makedirs(dest_dir)

    def new_file(self, log_path):
        print('Receiving "%s"' % self.file_name)
        self.current_file = self.file_name
        new_file = File(self)
        files[self.file_name] = new_file
        new_file.process_packet(self, log_path)


def receive(directory, log_path):
    PATH_DEST = directory
    print('Saving files to "%s"' % PATH_DEST)
    print('Using temp directory "%s"' % TEMP_PATH)
    print('Listening on UDP port %d...' % PORT)
    print('(Press Ctrl+Pause to quit)')
    p = Packet()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, PORT))
    while 1:
        packet, address = s.recvfrom(PACKET_SIZE)
        if not packet:
            break
        try:
            p.decoder(packet, log_path)
        except:
            print("Error while decoding packet: %s" % traceback.format_exc(1))
            traceback.print_exc()


def change_priority():
    if sys.platform == 'win32':
        # Windows:
        # process = win32process.GetCurrentProcess()
        # win32process.SetPriorityClass (process, win32process.REALTIME_PRIORITY_CLASS)
        pass
    else:
        # Unix:
        try:
            os.nice(-20)
        except:
            print("Access denied changing process priority. Please run again as root.")


def analyse_options():
    parser = optparse.OptionParser(usage="%prog [options] <file or directory>")

    parser.add_option("-a", dest="address", default="localhost", \
                      help="IP address of receiving computer")
    parser.add_option("-p", dest="port", \
                      help="UDP port", type="int", default=36016)

    (options, args) = parser.parse_args(sys.argv[1:])

    if len(args) != 1:
        parser.error("No file or directory was specified.")

    return (options, args)


if __name__ == '__main__':
    (options, args) = analyse_options()
    target = args[0]
    HOST = options.address
    PORT = options.port

    print("Starting BlindFTP")

    if not os.path.isdir(target):
        print("Target is not a valid directory.")
    else:
        if not os.path.exists(TEMP_PATH):
            os.makedirs(TEMP_PATH)
        PATH_DEST = target
        log_path = os.path.dirname(os.path.realpath(__file__))
        change_priority()
        receive(PATH_DEST, log_path)

    print("Complete!")
