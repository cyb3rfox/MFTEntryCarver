import mmap
from struct import unpack
from datetime import datetime
import argparse




def parseTimestamp(ts_bytes):

    bytes_low = unpack('<L', ts_bytes[0:4])[0]
    bytes_high = unpack('<L', ts_bytes[4:8])[0]
    try:
        return str(datetime.utcfromtimestamp((float(bytes_high) * 2 ** 32 + bytes_low) * 1e-7 - 11644473600))
    except:
        return "corrupt"



def parseFN(mftentry):


    last_attribute_pointer = 0;
    last_attribute_size = 0;
    names = []
    return_code = -1

    while 1:
        # locate header for File_Name attribute
        file_entry_offset = mftentry.find("\x30\x00\x00\x00", last_attribute_pointer + last_attribute_size)

        # if there is no FN return and proceed. Seems to be a broken entry
        if file_entry_offset == -1: break

        # calculate some offsets to check plausibility

        length_of_attribute_byte = mftentry[file_entry_offset + 4: file_entry_offset + 8]  # 4 bytes little endian

        # problem parsing length
        if len(length_of_attribute_byte) < 4:
            # print("Length: "+str(len(length_of_attribute_byte)))
            return_code = -2
            last_attribute_pointer = file_entry_offset
            last_attribute_size = 90
            continue


        # get length_of_attribute
        length_of_attribute = unpack('<I', length_of_attribute_byte)[0]

        # only accept realistic values, min should be int 89, maximum i'll put at int 1024 for now
        if length_of_attribute < 90 or length_of_attribute > 1024:
            # print length_of_attribute
            return -3   # if the first entry is already broken it does not make sense to scan for other after that

        # check if long or short. broken if not x01 or x02
        try:
            fn_type = mftentry[file_entry_offset + 89].encode("hex")
            if fn_type != "01" and fn_type != "02":
                # print "FN Type: "+fn_type
                return_code = -4
                last_attribute_pointer = file_entry_offset
                last_attribute_size = length_of_attribute
                continue
        except:
            return_code = -4
            last_attribute_pointer = file_entry_offset
            last_attribute_size = length_of_attribute
            continue

        fn_length = ord(mftentry[file_entry_offset + 88]) * 2 # it's character count not bytecount and utf16 so multiply by 2

        namestring = mftentry[file_entry_offset + 90:file_entry_offset + 90 + fn_length]

        # prepare for next round
        last_attribute_pointer = file_entry_offset
        last_attribute_size = length_of_attribute


        try:
            names.append(namestring.decode("UTF-16LE"))
        except:
            names.append("corrupt: len=" + str(len(names)))



    if len(names) == 0: return return_code;

    # timestamps are supposed to be the same for all fn attributes
    creation_time_bytes =  mftentry[file_entry_offset + 32 : file_entry_offset + 40]
    creation_time = parseTimestamp(creation_time_bytes)

    modification_time_bytes = mftentry[file_entry_offset + 40: file_entry_offset + 48]
    modification_time = parseTimestamp(creation_time_bytes)

    metachange_time_bytes = mftentry[file_entry_offset + 48: file_entry_offset + 56]
    metachange_time = parseTimestamp(creation_time_bytes)

    access_time_bytes = mftentry[file_entry_offset + 56: file_entry_offset + 64]
    access_time = parseTimestamp(creation_time_bytes)


    return 0, names, creation_time,modification_time,metachange_time,access_time



def parseData(mftentry):

    # locate header for Data attribute
    data_entry_offset = mftentry.find("\x80\x00\x00\x00")

    # if there is no Data return and proceed. Seems to be a broken entry
    if data_entry_offset == -1: return -21;

    # calculate some offsets to check plausibility

    length_of_attribute_byte = mftentry[data_entry_offset + 4: data_entry_offset + 8]  # 4 bytes little endian

    # problem parsing length
    if len(length_of_attribute_byte) < 4:
        # print("Length: "+str(len(length_of_attribute_byte)))
        return -22

    # get length_of_attribute
    length_of_attribute = unpack('<I', length_of_attribute_byte)[0]



    # only accept realistic values, min should be int 89, maximum i'll put at int 1024 for now
    if length_of_attribute < 50 or length_of_attribute > 1024:
        # print length_of_attribute
        return -23

    resident = ord(mftentry[data_entry_offset + 8])
    resident_data = 0
    if resident == 0: # 0 means it is resident. Microsoft seems to have a strange take on boolean
        resident_data = mftentry[data_entry_offset+64:data_entry_offset+length_of_attribute]

    return resident_data


def parseSTDInfo(mftentry):

    # locate header for File_Name attribute
    std_entry_offset = mftentry.find("\x10\x00\x00\x00")

    # if there is no FN return and proceed. Seems to be a broken entry
    if std_entry_offset == -1: return -31;

    # calculate some offsets to check plausibility

    length_of_attribute_byte = mftentry[std_entry_offset + 4: std_entry_offset + 8]  # 4 bytes little endian

    # problem parsing length
    if len(length_of_attribute_byte) < 4:
        # print("Length: "+str(len(length_of_attribute_byte)))
        return -32

    # get length_of_attribute
    length_of_attribute = unpack('<I', length_of_attribute_byte)[0]

    # only accept realistic values, min should be int 89, maximum i'll put at int 1024 for now
    if length_of_attribute < 30 or length_of_attribute > 1024:
        # print length_of_attribute
        return -33

    # timestamps
    creation_time_bytes = mftentry[std_entry_offset + 24: std_entry_offset + 32]
    creation_time = parseTimestamp(creation_time_bytes)

    modification_time_bytes = mftentry[std_entry_offset + 32: std_entry_offset + 40]
    modification_time = parseTimestamp(creation_time_bytes)

    metachange_time_bytes = mftentry[std_entry_offset + 40: std_entry_offset + 48]
    metachange_time = parseTimestamp(creation_time_bytes)

    access_time_bytes = mftentry[std_entry_offset + 48: std_entry_offset + 66]
    access_time = parseTimestamp(creation_time_bytes)



    return 0,creation_time,modification_time,metachange_time,access_time


def parse_entry (start_offset,mm):

    # read should be fine as it reads n bytes from the current pointer and then resets the pointer
    mm.seek(start_offset)
    mftentry = mm.read(1024)
    mm.seek(start_offset+4)



    fname = parseFN(mftentry)
    if fname < 0:
        return fname  # no need to continue when we have no name for the file


    data = parseData(mftentry)
    if data < 0:
        data = "data attribute corrupt"
    elif data == 0:
        data = "not resident"
    else:
        data = data.encode("hex")

    stdinfo = parseSTDInfo(mftentry)

    if stdinfo < 0:
        stdinfo = [0,"corrupt","corrupt","corrupt","corrupt"]

    try:
        print '{};{};{};{};{};{};{};{};{};{}'.format(fname[1],stdinfo[1],stdinfo[2],stdinfo[3],stdinfo[4],fname[2],fname[3],fname[4],fname[5],data)
    except: pass

    return 0




def load_and_start(filename, showstats):
    # Open File
    try:
        with open(filename, "r+b") as f:




            # Pointer pointing at the current find position - inc by 4 to jump over the current find
            file_pos_pointer = 0
            mm = mmap.mmap(f.fileno(), 0)

            # statistics
            allhits = 0
            no_fn = 0
            attr_len = 0
            unlikely_bounds = 0
            parsed = 0
            no_type = 0

            print "filenames;STD created;STD modified;STD Meta modified;STD accessed;FN created;FN modified;FN Meta modified;FN accessed"

            while 1:

                # locate (next) FILE entry
                file_pos_pointer = mm.find('\x46\x49\x4C\x45',file_pos_pointer)

                # break if there are no finds any more.
                if file_pos_pointer == -1: break

                # parse entry
                result = parse_entry(file_pos_pointer, mm)

                # update stats
                allhits = allhits + 1

                if result == -1:
                    no_fn = no_fn + 1
                if result == -2:
                    attr_len = attr_len + 1
                if result == -3:
                    unlikely_bounds = unlikely_bounds + 1
                if result == -4:
                    no_type = no_type + 1
                if result ==  0:
                    parsed = parsed + 1


                # adjust the pointer to jump over the magic bytes. Theoretical I could jump over the standard size of an entry (1024),
                # but that would assume, that there are no partial entries present. As it's unclear where all entries are coming from,
                # I'll only jump over the header.
                file_pos_pointer = file_pos_pointer + 4

        if showstats:
            print "++++++++++++++++++++++++++++++++++++++++++++++"
            print "+                    Stats                   +"
            print "++++++++++++++++++++++++++++++++++++++++++++++"
            print "Total processed : "+ str(allhits)
            print "No $FN          : "+ str(no_fn)
            print "No $FN Type     : "+ str(no_type)
            print "Unlikely Bounds : "+ str(unlikely_bounds)
            print "Other           : "+ str(attr_len)
            print "=============================================="
            print "Parsed          : "+ str(parsed)
    except IOError:
        print "Input file {} not found".format(filename)




parser = argparse.ArgumentParser(description='Carve files for MFT entries (eg. blkls output or memory dumps). Recovers filenames (long & short), timestamps ($STD & $FN) and data if resident. It will also parse '
                                             'half broken entries as long as at least one $FN entry is ok.')
parser.add_argument('filename',
                    help='blob filename')
parser.add_argument('-s',dest="stats",action='store_true',
                    help='show stats')

args = parser.parse_args()


filename =  args.filename
stats = args.stats

load_and_start(filename,stats)
