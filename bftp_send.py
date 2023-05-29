#!/usr/bin/env python3

import syslog
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
import threading
import time
import traceback

PACKET_SIZE = 65500  # maximum packet size
SEND_FILE_TIMES = 2
QUEUE_SLEEP_SECONDS = 5
SECONDS_BETWEEN_FILES = 1
MAX_FILENAME_LEN = 1024  # maximum filename size
DEBUG = False

CONT_LOOPING = True
THREAD_LOCK = threading.Lock()
QUEUE = {}

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


def send_empty_directory(source_path, dest_rel_path, num_session=None, num_current_session_packet=None):
    """Sends an empty directory

    source_path : source file path on local disk
    dest_rel_path   : relative path of the file on the destination machine
    num_session    : session number
    num_current_session_packet : packet counter
    """

    cur_loop = 1

    print("Sending directory %s" % (source_path))
    syslog.syslog(syslog.LOG_INFO, "bftp: Sending directory " + source_path)
    while cur_loop <= SEND_FILE_TIMES:
        if num_session is None:
            num_session = int(time.time())
            num_current_session_packet = 0

        length_dest_path = len(dest_rel_path)
        if length_dest_path > MAX_FILENAME_LEN:
            raise ValueError

        num_total_file_packets = 1

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # FORMAT_HEADER = "BBHQIIIIQfI"
        header = struct.pack(
            FORMAT_HEADER,
            PACKET_DIRECTORY,
            length_dest_path,
            0,
            0,
            num_session,
            num_current_session_packet,
            0,
            num_total_file_packets,
            0,
            0,
            0
        )

        packet = header + str(dest_rel_path).encode()
        s.sendto(packet, (HOST, PORT))
        num_current_session_packet += 1

        print("Transferred")
        syslog.syslog(syslog.LOG_INFO, "bftp: Transferred")
        cur_loop = cur_loop + 1

    print("")
    time.sleep(SECONDS_BETWEEN_FILES)
    return num_current_session_packet


def do_send_file(source_path, dest_rel_path, num_session=None, num_current_session_packet=None):
    """Sends one file

    source_path : source file path on local disk
    dest_rel_path   : relative path of the file on the destination machine
    num_session    : session number
    num_current_session_packet : packet counter
    """

    cur_loop = 1

    file_size = os.path.getsize(source_path)
    file_size_s = round(file_size / 1024)

    print("Sending file %s (%s KB)" % (source_path, "{:,}".format(file_size_s)))
    syslog.syslog(syslog.LOG_INFO, "bftp: Sending file " + source_path + " ({:,} KB)".format(file_size_s))
    if num_session is None:
        num_session = int(time.time())
        num_current_session_packet = 0

    file_mtime = os.path.getmtime(source_path)
    length_dest_path = len(dest_rel_path)
    if length_dest_path > MAX_FILENAME_LEN:
        raise ValueError

    secs_per_pkt = 1 / (options.speed / PACKET_SIZE)

#    f = open(source_path, 'rb')
#    buf = f.read(16384)
#    crc32 = binascii.crc32(buf)
#    while len(buf) != 0:
#        buf = f.read(16384)
#        crc32 = binascii.crc32(buf, crc32)
#    f.close()

    data_size_max = PACKET_SIZE - LENGTH_HEADER - length_dest_path
    num_total_file_packets = (file_size + data_size_max - 1) / data_size_max
    num_total_file_packets = int(math.ceil(num_total_file_packets))
    if num_total_file_packets == 0:
        num_total_file_packets = 1

    while cur_loop <= SEND_FILE_TIMES:
        remaining_data = file_size
        try:
            f = open(source_path, 'rb')
        except FileNotFoundError:
            print("File disappeared")
            syslog.syslog(syslog.LOG_INFO, "bftp: File disappeared")
            return num_current_session_packet

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        file_start_time = time.time()

        for num_current_file_packet in range(0, num_total_file_packets):
            pkt_start_time = time.time()

            if remaining_data > data_size_max:
                data_size = data_size_max
            else:
                data_size = remaining_data
            remaining_data -= data_size

            offset = f.tell()
            data = f.read(data_size)
            # FORMAT_HEADER = "BBHQIIIIQfI"
            header = struct.pack(
                FORMAT_HEADER,
                PACKET_FILE,
                length_dest_path,
                data_size,
                offset,
                num_session,
                num_current_session_packet,
                num_current_file_packet,
                num_total_file_packets,
                file_size,
                file_mtime,
                0 #crc32
            )

            packet = header + str(dest_rel_path).encode() + data
            s.sendto(packet, (HOST, PORT))
            num_current_session_packet += 1

            # generate progress bar
            progress = int(100 * (num_current_file_packet + 1) / num_total_file_packets)
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

            pkt_end_time = time.time()

            try:
                time.sleep(secs_per_pkt - (pkt_end_time - pkt_start_time))
            except:
                pass

        print()
        f.close()

        file_end_time = time.time()
        file_total_time = file_end_time - file_start_time
        speed_kbps = round((file_size / file_total_time) / 1024)

        print("Done in %.2f seconds (%s KB/s)" % (
            file_total_time, "{:,}".format(speed_kbps)))
        syslog.syslog(syslog.LOG_INFO, "bftp: Done sending " + source_path + " in %.2f seconds (%s KB/s)" % (file_total_time, "{:,}".format(speed_kbps)))
        cur_loop = cur_loop + 1

    print("")
    time.sleep(SECONDS_BETWEEN_FILES)
    return num_current_session_packet


def sync_tree(directory, delete):
    print('Synchronising directory %s' % directory)
    syslog.syslog(syslog.LOG_INFO, "bftp: Synchronising directory " + directory)

    directory = directory.rstrip("\\/")  # remove trailing slash (things break if it's present)

    num_session = int(time.time())
    num_packet_session = 0
    for dirname, subdirnamelist, filenamelist in os.walk(directory, topdown=False):
        relpath = "." + dirname[len(directory):]
        for filename in filenamelist:
            try:
                dirpath = os.path.join(dirname, filename).replace("\\", "/")
                tmprelpath = os.path.join(relpath, filename).replace("\\", "/")

                # dirname = fully qualified path excluding filename (e.g. y:\download\nt4 tsc\setup)
                # relpath = relative path from the directory in the function parameters excluding filename(e.g. .\nt4 tsc\setup)
                # filename = filename only (e.g. MSTSC.INF)
                # dirpath = fully qualified path including filename (e.g. y:/download/nt4 tsc/setup/MSTSC.INF)
                # tmprelpath = relative path from the directory in the function parameters including filename (e.g. ./nt4 tsc/setup/MSTSC.INF)

                num_packet_session = do_send_file(dirpath, tmprelpath, num_session, num_packet_session)

                if delete:
                    print("Removing source file")
                    syslog.syslog(syslog.LOG_INFO, "bftp: Removing source file")
                    os.remove(dirpath)
            except PermissionError:
                print("Permission denied opening file")
                syslog.syslog(syslog.LOG_INFO, "bftp: Permission denied opening file")
            except:
                traceback.print_exc()
        for subdirname in subdirnamelist:
            relsrc = os.path.join(dirname, subdirname).replace("\\", "/")
            reldst = "." + relsrc[len(directory):].replace("\\", "/")
            if len(os.listdir(relsrc)) == 0:
                num_packet_session = send_empty_directory(relsrc, reldst, num_session, num_packet_session)
                if delete:
                    os.rmdir(relsrc)


def send_queued_files(directory):
    while CONT_LOOPING:
        THREAD_LOCK.acquire()

        num_session = int(time.time())
        num_packet_session = 0

        file_successfully_sent = False

        if DEBUG:
            print('Dumping file queue')
            for item in QUEUE.items():
                print(item)

        for k, v in QUEUE.items():
            if v[0] == 0:
                old_file_size = v[1]
                tmprelpath = v[2]
                new_file_size = None
                try:
                    new_file_size = os.path.getsize(k)
                except FileNotFoundError:
                    print('WARNING: %s disappeared' % k)
                    syslog.syslog(syslog.LOG_INFO, "bftp: WARNING: " + k + " disappeared")
                    del QUEUE[k]
                    break
                except:
                    pass

                # when copying files in windows, it immediately sets target size = source size
                # it will hold a lock until copying completes (which causes permissionerror)
                permission_error = False
                try:
                    open(k).close()
                except PermissionError:
                    if DEBUG:
                        print('INFO: PermissionError opening %s' % k)
                    permission_error = True

                if old_file_size != new_file_size or new_file_size == None or permission_error:
                    # file isn't ready yet
                    QUEUE[k] = (QUEUE_SLEEP_SECONDS, new_file_size, tmprelpath)
                else:
                    # ready to send
                    THREAD_LOCK.release()
                    num_packet_session = do_send_file(k, tmprelpath, num_session, num_packet_session)
                    file_successfully_sent = True
                    try:
                        os.remove(k)
                    except:
                        # maybe it already got deleted by something else
                        pass
                    THREAD_LOCK.acquire()
                    del QUEUE[k]
                    break

        # clean up empty directories
        for dirname, subdirnamelist, filenamelist in os.walk(directory, topdown=False):
            for subdirname in subdirnamelist:
                relsrc = os.path.join(dirname, subdirname).replace("\\", "/")
                reldst = "." + relsrc[len(directory):].replace("\\", "/")
                if len(os.listdir(relsrc)) == 0:
                    num_packet_session = send_empty_directory(relsrc, reldst, num_session, num_packet_session)
                    file_successfully_sent = True
                    os.rmdir(relsrc)

        THREAD_LOCK.release()
        if not file_successfully_sent:
            time.sleep(1)
 

def enqueue_loop(directory):
    while CONT_LOOPING:
        THREAD_LOCK.acquire()

        for k, v in QUEUE.items():
            if v[0] > 0:
                QUEUE[k] = (v[0] - 1, v[1], v[2])

        directory = directory.rstrip("\\/")  # remove trailing slash (things break if it's present)

        for dirname, subdirnamelist, filenamelist in os.walk(directory, topdown=False):
            relpath = "." + dirname[len(directory):]
            for filename in filenamelist:
                dirpath = os.path.join(dirname, filename).replace("\\", "/")
                tmprelpath = os.path.join(relpath, filename).replace("\\", "/")

                # dirpath = fully qualified path including filename (e.g. y:/download/nt4 tsc/setup/MSTSC.INF)
                # tmprelpath = relative path from the directory in the function parameters including filename (e.g. ./nt4 tsc/setup/MSTSC.INF)

                if dirpath not in QUEUE:
                    file_size = None
                    try:
                        file_size = os.path.getsize(dirpath)
                    except:
                        pass

                    print('Queueing %s' % dirpath)
                    syslog.syslog(syslog.LOG_INFO, "bftp: Queueing " + dirpath)
                    QUEUE[dirpath] = (QUEUE_SLEEP_SECONDS, file_size, tmprelpath)

        THREAD_LOCK.release()
        time.sleep(1)


def analyse_options():
    parser = optparse.OptionParser(usage="%prog [options] <file or directory>")

    parser.add_option("-s", "--send", action="store_true", dest="send_file", \
                      default=False, help="Send single file")
    parser.add_option("-t", "--tree", action="store_true", dest="sync_tree", \
                      default=False, help="Send directory tree")
    parser.add_option("-a", dest="address", default="localhost", \
                      help="IP address of receiving computer")
    parser.add_option("-p", dest="port", \
                      help="UDP port", type="int", default=36016)
    parser.add_option("-l", dest="speed", \
                      help="Speed limit in bytes/s (default 12000000)", type="int", default=12000000)
    parser.add_option("-b", "--loop", action="store_true", dest="loop", \
                      default=False, help="Send files in loop (forces -t and -d)")
    parser.add_option("-P", dest="pause", \
                      help="Pause n seconds after every loop (used with -b)", type="int", default=5)
    parser.add_option("-d", "--delete", action="store_true", dest="delete", \
                      help="Delete files from after sending", default=False)
    parser.add_option("-x", "--debug", action="store_true", dest="debug", \
                      help="Debug mode", default=False)

    (options, args) = parser.parse_args(sys.argv[1:])

    num_actions = 0
    if options.send_file: num_actions += 1
    if options.sync_tree: num_actions += 1
    if num_actions != 1:
        parser.error("No action was specified.")
    if len(args) != 1:
        parser.error("No file or directory was specified.")

    return (options, args)


def has_live_threads(threads):
    return True in [t.is_alive() for t in threads]


if __name__ == '__main__':
    (options, args) = analyse_options()
    target = args[0]
    HOST = options.address
    PORT = options.port

    print("Starting BlindFTP")
    syslog.syslog(syslog.LOG_INFO, "bftp: Starting BlindFTP")

    if options.debug:
        DEBUG = True

    if options.send_file:
        # sends a single file then quits
        if not os.path.isfile(target):
            print("Target is not a valid file.")
        else:
            do_send_file(target, os.path.basename(target))
    elif options.sync_tree:
        # sync directory tree
        #if not os.path.isdir(target):
        #    print("Target is not a valid directory.")
        #else:
        if 1:
            if options.loop:
                # sends directory tree in a loop
                threads = list()
                enqueue_thread = threading.Thread(target=enqueue_loop, args=(target,))
                send_queue_thread = threading.Thread(target=send_queued_files, args=(target,))
                threads.append(enqueue_thread)
                threads.append(send_queue_thread)
                enqueue_thread.start()
                send_queue_thread.start()

                while has_live_threads(threads):
                    try:
                        # synchronization timeout of threads kill
                        [t.join(1) for t in threads
                         if t is not None and t.is_alive()]
                    except KeyboardInterrupt:
                        # Ctrl-C handling and send kill to threads
                        print("Sending kill to threads...")
                        CONT_LOOPING = False
            else:
                # sends directory tree once then quits
                sync_tree(target, options.delete)

    CONT_LOOPING = False
    print("Complete!")
    syslog.syslog(syslog.LOG_INFO, "bftp: Complete!")
