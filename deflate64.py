from dataclasses import dataclass
import enum


INFLATE_MODE = enum(
    "HEAD",       # i: waiting for magic header */
    "FLAGS",      # i: waiting for method and flags (gzip) */
    "TIME",       # i: waiting for modification time (gzip) */
    "OS",         # i: waiting for extra flags and operating system (gzip) */
    "EXLEN",      # i: waiting for extra length (gzip) */
    "EXTRA",      # i: waiting for extra bytes (gzip) */
    "NAME",       # i: waiting for end of file name (gzip) */
    "COMMENT",    # i: waiting for end of comment (gzip) */
    "HCRC",       # i: waiting for header crc (gzip) */
    "DICTID",     # i: waiting for dictionary check value */
    "DICT",       # waiting for inflateSetDictionary() call */
        "TYPE",       # i: waiting for type bits, including last-flag bit */
        "TYPEDO",     # i: same, but skip check to exit inflate on new block */
        "STORED",     # i: waiting for stored size (length and complement) */
        "COPY",       # i/o: waiting for input or output to copy stored block */
        "TABLE",      # i: waiting for dynamic block table lengths */
        "LENLENS",    # i: waiting for code length code lengths */
        "CODELENS",   # i: waiting for length/lit and distance code lengths */
            "LEN",        # i: waiting for length/lit code */
            "LENEXT",     # i: waiting for length extra bits */
            "DIST",       # i: waiting for distance code */
            "DISTEXT",    # i: waiting for distance extra bits */
            "MATCH",      # o: waiting for output space to copy string */
            "LIT",        # o: waiting for output space to write literal */
    "CHECK",      # i: waiting for 32-bit check value */
    "LENGTH",     # i: waiting for 32-bit length (gzip) */
    "DONE",       # finished check, done -- remain here until reset */
    "ACAB_BAD",        # got a data error -- remain here until reset */
    "MEM",        # got an inflate() memory error -- remain here until reset */
    "SYNC"        # looking for synchronization bytes to restart inflate() */
)

@dataclass
class code:
    op: str           # operation, extra bits, table bits
    bits: bytes # TODO this may need to be bytearray, or just plain str         # bits in this part of the code
    val: int         # offset in table or code value


@dataclass
class inflate_state:
    mode: INFLATE_MODE          # current inflate mode
    last: int                 # true if processing last block
    wrap: int                  # bit 0 true for zlib, bit 1 true for gzip
    havedict: int               # true if dictionary provided
    flags: int                  # gzip header method and flags (0 if zlib)
    dmax: int              # zlib header max distance (INFLATE_STRICT)
    check: int        # protected copy of check value
    total: int        # protected copy of output count
        # sliding window
    wbits: int             # log base 2 of requested window size
    wsize: int            # window size or zero if not using window
    whave: int             # valid bytes in the window
    write: int             # window write index
    window: str  # allocated sliding window, if needed
        # bit accumulator
    hold: int         # input bit accumulator
    bits: int              # number of bits in "in"
        # for string and stored block copying
    length: int            #literal or length of data to copy
    offset: int            # distance back to copy string from
        # for table and code decoding
    extra: int             # extra bits needed
        # fixed and dynamic code tables
    lencode: code    #starting table for length/literal codes
    distcode: code   # starting table for distance codes
    lenbits: int           # index bits for lencode
    distbits: int           # index bits for distcode
        # dynamic table building
    ncode: int             # number of code length code lengths
    nlen: int              # number of length code lengths
    ndist: int             # number of distance code lengths
    have: int              # number of code lengths in lens[]
    next: code             # next available space in codes[]
    lens: list   # temporary storage for code lengths
    work: list   # work area for code table building
    codes: list         # space for code tables


@dataclass
class z_stream64:
    next_in: int  # next input byte pointer
    total_in: int  # total nb of input bytes read so far
    avail_in: int   # number of bytes available at next_in

    avail_out: int # remaining free space at next_out
    next_out: int # pointer to next output byte should be put there
    total_out: int # total nb of bytes output so far

    state: inflate_state  # Pointer to internal state not visible by applications, typeof state namedtuple

    adler: int # adler32 value of the uncompressed data
    data_type: int  # best guess about the data type: binary or text

    """ function prototypes """
#  local void fixedtables OF((struct inflate_state FAR *state))
#  local int updatewindow OF((z_stream64p strm, unsigned out))
#  local int inflate_table OF((codetype type, unsigned short FAR *lens,
#                               unsigned codes, code FAR * FAR *table,
#                               unsigned FAR *bits, unsigned short FAR *work))


def inflate64Init2(strm, windowBits):

    if (strm == Z_NULL) return Z_STREAM_ERROR
    state = inflate_state()
    if (state == Z_NULL) return Z_MEM_ERROR
    print("inflate: allocated\n")
    strm.state = inflate_state()
    if (windowBits < 0):
        state.wrap = 0
        windowBits = -windowBits
    else:
        state.wrap = (windowBits >> 4) + 1
    if (windowBits < 8 or windowBits > MAX_WBITS64):
        free(state)
        strm.state = Z_NULL
        return Z_STREAM_ERROR
    state.wbits = windowBits
    state.window = Z_NULL
    strm.total_in = strm.total_out = state.total = 0
    strm.adler = 1        """ to support ill-conceived Java test suite """
    state.mode = INFLATE_MODE.HEAD
    state.last = 0
    state.havedict = 0
    state.dmax = 32768
    state.wsize = 0
    state.whave = 0
    state.write = 0
    state.hold = 0
    state.bits = 0
    state.lencode = state.distcode = state.next = state.codes
    print("inflate: reset\n")
    return Z_OK

"""
   Return state with length and distance decoding tables and index sizes set to
   fixed code decoding.  Normally this returns fixed tables from inffixed.h.
   If BUILDFIXED is defined, then instead this routine builds the tables the
   first time it's called, and returns those tables the first time and
   thereafter.  This reduces the size of the code by about 2K bytes, in
   exchange for a little execution time.  However, BUILDFIXED should not be
   used for threaded applications, since the rewriting of the tables and virgin
   may not be thread-safe.
 """
def fixedtables(state):
    global bits

    virgin = 1
    lenfix = code()
    distfix = code()
    fixed = [ code() ] * 544

    """ build fixed huffman tables if first call (may not be thread safe) """
    if (virgin):
        unsigned sym, bits
        next_ = code()

        """ literal/length table """
        sym = 0
        while (sym < 144) state.lens[sym++] = 8
        while (sym < 256) state.lens[sym++] = 9
        while (sym < 280) state.lens[sym++] = 7
        while (sym < 288) state.lens[sym++] = 8
        next_ = fixed
        lenfix = next_
        bits = 9
        inflate_table(LENS, state.lens, 288, next_, &(bits), state.work)

        """ distance table """
        sym = 0
        while (sym < 32) state.lens[sym++] = 5
        distfix = next_
        bits = 5
        inflate_table(DISTS, state.lens, 32, next_, bits_, state.work)

        """ do this just once """
        virgin = 0
    state.lencode = lenfix
    state.lenbits = 9
    state.distcode = distfix
    state.distbits = 5

"""
   Update the window with the last wsize (normally 32K) bytes written before
   returning.  If window does not exist yet, create it.  This is only called
   when a window is already in use, or when output has been written during this
   inflate call, but the end of the deflate stream has not been reached yet.
   It is also called to create a window for dictionary data when a dictionary
   is loaded.

   Providing output buffers larger than 32K to inflate() should provide a speed
   advantage, since only the last 32K of output is copied to the sliding window
   upon return from inflate(), and since all distances after the first 32K of
   output will fall in the output data, making match copies simpler and faster.
   The advantage may be dependent on the size of the processor's data caches.
 """
def updatewindow(strm, out):
    state = inflate_state()

    """ if it hasn't been done already, allocate space for the window """
    if (state.window == Z_NULL):
        state.window = (unsigned char FAR *)cli_calloc(1U << state.wbits, sizeof(unsigned char))
        if (state.window == Z_NULL) return 1

    """ if window not in use yet, initialize """
    if (state.wsize == 0):
        state.wsize = 1 << state.wbits
        state.write = 0
        state.whave = 0

    """ copy state.wsize or less output bytes into the circular window """
    copy = out - strm.avail_out
    if (copy >= state.wsize):
        memcpy(state.window, strm.next_out - state.wsize, state.wsize)
        state.write = 0
        state.whave = state.wsize
    else:
        dist = state.wsize - state.write
        if (dist > copy) dist = copy
        memcpy(state.window + state.write, strm.next_out - copy, dist)
        copy -= dist
        if (copy):
            memcpy(state.window, strm.next_out - copy, copy)
            state.write = copy
            state.whave = state.wsize
        else:
            state.write += dist
            if (state.write == state.wsize) state.write = 0
            if (state.whave < state.wsize) state.whave += dist
    return 0

""" Macros for inflate(): """

""" check function to use adler32() for zlib or crc32() for gzip """
def UPDATE(check, buf, len):
    return adler32(check, buf, len)


# TODO is this a global or do we want to refactor this to be passsed?
#  state = None
have = None
hold = None
put = None
hold = None
bits = None

""" Load registers with state in_ inflate() for speed """
def LOAD():
    global put, left, next_, have, hold, bits
    put = strm.next_out
    left = strm.avail_out
    next_ = strm.next_in
    have = strm.avail_in
    hold = state.hold
    bits = state.bits

""" Restore state from registers in inflate() """
def RESTORE():
    global strm
    strm.next_out = put
    strm.avail_out = left
    strm.next_in = next_
    strm.avail_in = have
    state.hold = hold
    state.bits = bits

""" Clear the input bit accumulator """
def INITBITS():
    global hold, bits
    hold = 0
    bits = 0

""" Get a byte of input into the bit accumulator, or return from inflate()
   if there is no input available. """
def PULLBYTE():
    global have, hold, bits, out, in_
    if (have == 0):
        """
           Return from inflate(), updating the total counts and the check value.
           If there was no progress during the inflate() call, return a buffer
           error.  Call updatewindow() to create and/or update the window state.
           Note: a memory error from inflate() is non-recoverable.
        """
        RESTORE()
        if (state.wsize or (state.mode < CHECK and out != strm.avail_out))
            if (updatewindow(strm, out)):
                state.mode = INFLATE_MODE.MEM
                return Z_MEM_ERROR
            }
        in_ -= strm.avail_in
        out -= strm.avail_out
        strm.total_in += in_
        strm.total_out += out
        state.total += out
        if (state.wrap and out)
            strm.adler = state.check = UPDATE(state.check, strm.next_out - out, out)
        strm.data_type = state.bits + (64 if state.last else 0) +
                          (128 if state.mode == INFLATE_MODE.TYPE else 0)
        if (((in_ == 0 and out == 0) or flush == Z_FINISH) and ret == Z_OK)
            ret = Z_BUF_ERROR
        return ret
    have -= 1
    hold += (unsigned long)(*next_++) << bits
    bits += 8

""" Assure that there are at least n bits in the bit accumulator.  If there is
   not enough available input to do that, then return from inflate(). """
def NEEDBITS(n):
    while (bits < (n)):
        PULLBYTE()

""" Return the low n bits of the bit accumulator (n < 16) """
def BITS(n):
    return (hold & ((1 << (n)) - 1))

""" Remove n bits from the bit accumulator """
def DROPBITS(n):
    global hold, bits
    hold >>= (n)
    bits -= (n)

""" Remove zero to seven bits as needed to go to a byte boundary """
def BYTEBITS():
    global hold, bits
    hold >>= bits & 7
    bits -= bits & 7

""" Reverse the bytes in a 32-bit value """
def REVERSE(q):
    return ((((q) >> 24) & 0xff) + (((q) >> 8) & 0xff00) + \
     (((q) & 0xff00) << 8) + (((q) & 0xff) << 24))

"""
   inflate() uses a state machine to process as much input data and generate as
   much output data as possible before returning.  The state machine is
   structured roughly as follows:

    for () switch (state) {
    ...
    case STATEn:
        if (not enough input data or output space to make progress)
            return
        ... make progress ...
        state = STATEm
        break
    ...
    }

   so when inflate() is called again, the same case is attempted again, and
   if the appropriate resources are provided, the machine proceeds to the
   next state.  The NEEDBITS() macro is usually the way the state evaluates
   whether it can proceed or should return.  NEEDBITS() does the return if
   the requested bits are not available.  The typical use of the BITS macros
   is:

        NEEDBITS(n)
        ... do something with BITS(n) ...
        DROPBITS(n)

   where NEEDBITS(n) either returns from inflate() if there isn't enough
   input left to load n bits into the accumulator, or it continues.  BITS(n)
   gives the low n bits in the accumulator.  When done, DROPBITS(n) drops
   the low n bits off the accumulator.  INITBITS() clears the accumulator
   and sets the number of available bits to zero.  BYTEBITS() discards just
   enough bits to put the accumulator on a byte boundary.  After BYTEBITS()
   and a NEEDBITS(8), then BITS(8) would return the next byte in the stream.

   NEEDBITS(n) uses PULLBYTE() to get an available byte of input, or to return
   if there is no input available.  The decoding of variable length codes uses
   PULLBYTE() directly in order to pull just enough bytes to decode the next
   code, and no more.

   Some states loop until they get enough input, making sure that enough
   state information is maintained to continue the loop where it left off
   if NEEDBITS() returns in the loop.  For example, want, need, and keep
   would all have to actually be part of the saved state in case NEEDBITS()
   returns:

    case STATEw:
        while (want < need):
            NEEDBITS(n)
            keep[want++] = BITS(n)
            DROPBITS(n)
        }
        state = STATEx
    case STATEx:

   As shown above, if the next state is also the next case, then the break
   is omitted.

   A state may also return if there is not enough output space available to
   complete that state.  Those states are copying stored data, writing a
   literal byte, and copying a matching string.

   When returning, a "goto inf_leave" is used to update the total counters,
   update the check value, and determine whether any progress has been made
   during that inflate() call in order to return the proper return code.
   Progress is defined as a change in either strm.avail_in or strm.avail_out.
   When there is a window, goto inf_leave will update the window with the last
   output written.  If a goto inf_leave occurs in the middle of decompression
   and there is no window currently, goto inf_leave will create one and copy
   output to the window for the next call of inflate().

   In this implementation, the flush parameter of inflate() only affects the
   return code (per zlib.h).  inflate() always writes as much as possible to
   strm.next_out, given the space available and the provided input--the effect
   documented in zlib.h of Z_SYNC_FLUSH.  Furthermore, inflate() always defers
   the allocation of and copying into a sliding window until necessary, which
   provides the effect documented in zlib.h for Z_FINISH when the entire input
   stream available.  So the only thing the flush parameter actually does is:
   when flush is set to Z_FINISH, inflate() cannot return Z_OK.  Instead it
   will return Z_BUF_ERROR if it has not reached the end of the stream.
 """

def inflate64(strm, flush):
    #  unsigned char FAR *next_    """ next input """
    #  unsigned char FAR *put     """ next output """
    #  unsigned have, left        """ available input and output """
    #  unsigned long hold         """ bit buffer """
    #  unsigned bits              """ bits in bit buffer """
    #  unsigned in, out           """ save starting available input and output """
    #  unsigned copy              """ number of stored or match bytes to copy """
    #  unsigned char FAR *from    """ where to copy match bytes from """
    #  code this                  """ current decoding table entry """
    #  code last                  """ parent table entry """
    #  unsigned len               """ length to copy for repeats, bits to drop """
    #  int ret                    """ return code """
    #  static const unsigned short order[19] = """ permutation of code lengths """
    """ permutation of code lengths """
    order = {
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
    }

    if (
        strm == Z_NULL or strm.state == Z_NULL or strm.next_out == Z_NULL or (
            strm.next_in == Z_NULL and strm.avail_in != 0
        )
    ):
        return Z_STREAM_ERROR

    state = inflate_state()
    if (state.mode == INFLATE_MODE.TYPE) state.mode = INFLATE_MODE.TYPEDO      """ skip check """
    LOAD()
    in_ = have
    out = left
    ret = Z_OK

    # TODO: I *think* these `break` statements should actually be `continue`s?
    while True:
        if state.mode == INFLATE_MODE.HEAD:
            if (state.wrap == 0):
                state.mode = INFLATE_MODE.TYPEDO
                break
            NEEDBITS(16)
            if (
                ((BITS(8) << 8) + (hold >> 8)) % 31):
                state.mode = INFLATE_MODE.ACAB_BAD
                break
            if (BITS(4) != Z_DEFLATED):
                state.mode = INFLATE_MODE.ACAB_BAD
                break
            DROPBITS(4)
            len = BITS(4) + 8
            if (len > state.wbits):
                state.mode = INFLATE_MODE.ACAB_BAD
                break
            state.dmax = 1 << len
            print("inflate:   zlib header ok\n")
            #TODO find python implementation of adler32
            strm.adler = state.check = adler32(0, Z_NULL, 0)
            state.mode = DICTID if INFLATE_MODE.hold & 0x200 else TYPE
            INITBITS()
            break
        elif state.mode == INFLATE_MODE.DICTID:
            NEEDBITS(32)
            strm.adler = state.check = REVERSE(hold)
            INITBITS()
            state.mode = INFLATE_MODE.DICT
        elif state.mode == INFLATE_MODE.DICT:
            RESTORE()
            return Z_NEED_DICT
        elif state.mode == INFLATE_MODE.TYPE:
            if (flush == Z_BLOCK):
                """
                   Return from inflate(), updating the total counts and the check value.
                   If there was no progress during the inflate() call, return a buffer
                   error.  Call updatewindow() to create and/or update the window state.
                   Note: a memory error from inflate() is non-recoverable.
                """
                RESTORE()
                if (state.wsize or (state.mode < CHECK and out != strm.avail_out))
                    if (updatewindow(strm, out)):
                        state.mode = INFLATE_MODE.MEM
                        return Z_MEM_ERROR
                in_ -= strm.avail_in
                out -= strm.avail_out
                strm.total_in += in_
                strm.total_out += out
                state.total += out
                if (state.wrap and out)
                    strm.adler = state.check = UPDATE(state.check, strm.next_out - out, out)
                strm.data_type = state.bits + (64 if state.last else 0) +
                                  (128 if state.mode == INFLATE_MODE.TYPE else 0)
                if (((in_ == 0 and out == 0) or flush == Z_FINISH) and ret == Z_OK)
                    ret = Z_BUF_ERROR
                return ret
        elif state.mode == INFLATE_MODE.TYPEDO:
            if (state.last):
                BYTEBITS()
                state.mode = INFLATE_MODE.CHECK
                break
            NEEDBITS(3)
            state.last = BITS(1)
            DROPBITS(1)
            typedo_mode = BITS(2)
            """ stored block """
            if typedo_mode == 0:
                print(f"inflate:     stored block%s\n ${state.last}")
                state.mode = INFLATE_MODE.STORED
                break
            """ fixed block """
            elif typedo_mode == 1:
                fixedtables(state)
                print(f"inflate:     fixed codes block%s\n state.last ${state.last}")
                """ decode codes """
                state.mode = INFLATE_MODE.LEN
                break
            """ dynamic block """
            elif typedo_mode == 2:
                print(f"inflate:     dynamic codes block%s\nstate.last ${state.last}")
                state.mode = INFLATE_MODE.TABLE
                break
            elif typedo_mode == 3:
                state.mode = INFLATE_MODE.ACAB_BAD
            DROPBITS(2)
            break
        elif state.mode == INFLATE_MODE.STORED:
            BYTEBITS()                         """ go to byte boundary """
            NEEDBITS(32)
            if ((hold & 0xffff) != ((hold >> 16) ^ 0xffff)):
                state.mode = INFLATE_MODE.ACAB_BAD
                break
            state.length = hold & 0xffff
            Tracev((stderr, "inflate:       stored length %u\n",
                    state.length))
            INITBITS()
            state.mode = INFLATE_MODE.COPY
        elif state.mode == INFLATE_MODE.COPY:
            copy = state.length
            if (copy):
                if (copy > have) copy = have
                if (copy > left) copy = left
                if (copy == 0):
                    """
                       Return from inflate(), updating the total counts and the check value.
                       If there was no progress during the inflate() call, return a buffer
                       error.  Call updatewindow() to create and/or update the window state.
                       Note: a memory error from inflate() is non-recoverable.
                    """
                    RESTORE()
                    if (state.wsize or (state.mode < CHECK and out != strm.avail_out))
                        if (updatewindow(strm, out)):
                            state.mode = INFLATE_MODE.MEM
                            return Z_MEM_ERROR
                        }
                    in_ -= strm.avail_in
                    out -= strm.avail_out
                    strm.total_in += in_
                    strm.total_out += out
                    state.total += out
                    if (state.wrap and out)
                        strm.adler = state.check = UPDATE(state.check, strm.next_out - out, out)
                    strm.data_type = state.bits + (64 if state.last else 0) +
                                      (128 if state.mode == INFLATE_MODE.TYPE else 0)
                    if (((in == 0 and out == 0) or flush == Z_FINISH) and ret == Z_OK)
                        ret = Z_BUF_ERROR
                    return ret
                memcpy(put, next, copy)
                have -= copy
                next_ += copy
                left -= copy
                put += copy
                state.length -= copy
                break
            print("inflate:       stored end\n")
            state.mode = INFLATE_MODE.TYPE
            break
        elif state.mode == INFLATE_MODE.TABLE:
            NEEDBITS(14)
            state.nlen = BITS(5) + 257
            DROPBITS(5)
            state.ndist = BITS(5) + 1
            DROPBITS(5)
            state.ncode = BITS(4) + 4
            DROPBITS(4)
            if (state.nlen > 286 or state.ndist > 30):
                state.mode = INFLATE_MODE.ACAB_BAD
                break
            print("inflate:       table sizes ok\n")
            state.have = 0
            state.mode = INFLATE_MODE.LENLENS
        elif state.mode == INFLATE_MODE.LENLENS:
            while (state.have < state.ncode):
                NEEDBITS(3)
                state.lens[order[state.have++]] = (unsigned short)BITS(3)
                DROPBITS(3)
            while (state.have < 19)
                state.lens[order[state.have++]] = 0
            state.next = state.codes
            state.lencode = (code const FAR *)(state.next)
            state.lenbits = 7
            ret = inflate_table(CODES, state.lens, 19, &(state.next),
                                &(state.lenbits), state.work)
            if (ret):
                state.mode = INFLATE_MODE.ACAB_BAD
                break
            print("inflate:       code lengths ok\n")
            state.have = 0
            state.mode = INFLATE_MODE.CODELENS
        elif state.mode == INFLATE_MODE.CODELENS:
            while (state.have < state.nlen + state.ndist):
                for ():
                    this = state.lencode[BITS(state.lenbits)]
                    if ((this.bits) <= bits) break
                    PULLBYTE()
                if (this.val < 16):
                    NEEDBITS(this.bits)
                    DROPBITS(this.bits)
                    state.lens[state.have++] = this.val
                else:
                    if (this.val == 16):
                        NEEDBITS(this.bits + 2)
                        DROPBITS(this.bits)
                        if (state.have == 0):
                            state.mode = INFLATE_MODE.ACAB_BAD
                            break
                        len = state.lens[state.have - 1]
                        copy = 3 + BITS(2)
                        DROPBITS(2)
                    else if (this.val == 17):
                        NEEDBITS(this.bits + 3)
                        DROPBITS(this.bits)
                        len = 0
                        copy = 3 + BITS(3)
                        DROPBITS(3)
                    else:
                        NEEDBITS(this.bits + 7)
                        DROPBITS(this.bits)
                        len = 0
                        copy = 11 + BITS(7)
                        DROPBITS(7)
                    if (state.have + copy > state.nlen + state.ndist):
                        state.mode = INFLATE_MODE.ACAB_BAD
                        break
                    while (copy--)
                        state.lens[state.have++] = (unsigned short)len

            """ handle error breaks in while """
            if (state.mode == INFLATE_MODE.ACAB_BAD) break

            """ build code tables """
            state.next = state.codes
            state.lencode = code(state.next)
            state.lenbits = 9
            ret = inflate_table(LENS, state.lens, state.nlen, state.next,
                                state.lenbits, state.work)
            if (ret):
                state.mode = INFLATE_MODE.ACAB_BAD
                break
            state.distcode = code(state.next)
            state.distbits = 6
            ret = inflate_table(DISTS, state.lens + state.nlen, state.ndist,
                            state.next, state.distbits, state.work)
            if (ret):
                state.mode = INFLATE_MODE.ACAB_BAD
                break
            print("inflate:       codes ok\n")
            state.mode = INFLATE_MODE.LEN
        elif state.mode == INFLATE_MODE.LEN:
            while True:
                this = state.lencode[BITS(state.lenbits)]
                if ((this.bits) <= bits) break
                PULLBYTE()
            if (this.op and (this.op & 0xf0) == 0):
                last = this
                for ():
                    this = state.lencode[last.val +
                            (BITS(last.bits + last.op) >> last.bits)]
                    if ((last.bits + this.bits) <= bits) break
                    PULLBYTE()
                DROPBITS(last.bits)
            DROPBITS(this.bits)
            state.length = this.val
            if ((int)(this.op) == 0):
                Tracevv((stderr, this.val >= 0x20 and this.val < 0x7f ?
                        "inflate:         literal '%c'\n" :
                        "inflate:         literal 0x%02x\n", this.val))
                state.mode = INFLATE_MODE.LIT
                break
            Tracevv((stderr, "inflate:         op %u\n", this.op))
            if (this.op & 32):
                Tracevv((stderr, "inflate:         end of block\n"))
                state.mode = INFLATE_MODE.TYPE
                break
            if (this.op & 64):
                state.mode = INFLATE_MODE.ACAB_BAD
                break
            state.extra = (this.op) & 31
            state.mode = INFLATE_MODE.LENEXT
        elif state.mode == INFLATE_MODE.LENEXT:
            if (state.extra):
                NEEDBITS(state.extra)
                state.length += BITS(state.extra)
                DROPBITS(state.extra)
            print(stderr, "inflate:         length %u\n", state.length)
            for () {
            state.mode = INFLATE_MODE.DIST
        elif state.mode == INFLATE_MODE.DIST:
                this = state.distcode[BITS(state.distbits)]
                if ((this.bits) <= bits) break
                PULLBYTE()
            if ((this.op & 0xf0) == 0):
                last = this
                for () {
                    this = state.distcode[last.val +
                            (BITS(last.bits + last.op) >> last.bits)]
                    if ((last.bits + this.bits) <= bits) break
                    PULLBYTE()
                }
                DROPBITS(last.bits)
            DROPBITS(this.bits)
            if (this.op & 64):
                state.mode = INFLATE_MODE.ACAB_BAD
                break
            Tracevv((stderr, "inflate:        val %u\n", state.offset))
            state.offset = this.val
            state.extra = (this.op) & 15
            state.mode = INFLATE_MODE.DISTEXT
        elif state.mode == INFLATE_MODE.DISTEXT:
            if (state.extra):
                NEEDBITS(state.extra)
                state.offset += BITS(state.extra)
                DROPBITS(state.extra)
#ifdef INFLATE_STRICT
            if (state.offset > state.dmax):
                state.mode = INFLATE_MODE.ACAB_BAD
                break
#endif
            if (state.offset > state.whave + out - left):
                state.mode = INFLATE_MODE.ACAB_BAD
                break
            Tracevv((stderr, "inflate:         distance %u\n", state.offset))
            state.mode = INFLATE_MODE.MATCH
        elif state.mode == INFLATE_MODE.MATCH:
            if (left == 0):
                """
                   Return from inflate(), updating the total counts and the check value.
                   If there was no progress during the inflate() call, return a buffer
                   error.  Call updatewindow() to create and/or update the window state.
                   Note: a memory error from inflate() is non-recoverable.
                """
                RESTORE()
                if (state.wsize or (state.mode < CHECK and out != strm.avail_out))
                    if (updatewindow(strm, out)):
                        state.mode = INFLATE_MODE.MEM
                        return Z_MEM_ERROR
                    }
                in_ -= strm.avail_in
                out -= strm.avail_out
                strm.total_in += in_
                strm.total_out += out
                state.total += out
                if (state.wrap and out)
                    strm.adler = state.check = UPDATE(state.check, strm.next_out - out, out)
                strm.data_type = state.bits + (64 if state.last else 0) +
                                  (128 if state.mode == INFLATE_MODE.TYPE else 0)
                if (((in == 0 and out == 0) or flush == Z_FINISH) and ret == Z_OK)
                    ret = Z_BUF_ERROR
                return ret
            copy = out - left
            if (state.offset > copy):         """ copy from window """
                copy = state.offset - copy
                if (copy > state.write):
                    copy -= state.write
                    from = state.window + (state.wsize - copy)
                else
                    from = state.window + (state.write - copy)
                if (copy > state.length) copy = state.length
            else:                              """ copy from output """
                from = put - state.offset
                copy = state.length
            if (copy > left) copy = left
            left -= copy
            state.length -= copy
            do {
                *put++ = *from++
            } while (--copy)
            if (state.length == 0) state.mode = INFLATE_MODE.LEN
            break
        elif state.mode == INFLATE_MODE.LIT:
            if (left == 0):
                """
                   Return from inflate(), updating the total counts and the check value.
                   If there was no progress during the inflate() call, return a buffer
                   error.  Call updatewindow() to create and/or update the window state.
                   Note: a memory error from inflate() is non-recoverable.
                """
                RESTORE()
                if (state.wsize or (state.mode < CHECK and out != strm.avail_out))
                    if (updatewindow(strm, out)):
                        state.mode = INFLATE_MODE.MEM
                        return Z_MEM_ERROR
                    }
                in_ -= strm.avail_in
                out -= strm.avail_out
                strm.total_in += in_
                strm.total_out += out
                state.total += out
                if (state.wrap and out)
                    strm.adler = state.check = UPDATE(state.check, strm.next_out - out, out)
                strm.data_type = state.bits + (64 if state.last else 0) +
                                  (128 if state.mode == INFLATE_MODE.TYPE else 0)
                if (((in == 0 and out == 0) or flush == Z_FINISH) and ret == Z_OK)
                    ret = Z_BUF_ERROR
                return ret
            *put++ = (unsigned char)(state.length)
            left--
            state.mode = INFLATE_MODE.LEN
            break
        elif state.mode == INFLATE_MODE.CHECK:
            if (state.wrap):
                NEEDBITS(32)
                out -= left
                strm.total_out += out
                state.total += out
                if (out)
                    strm.adler = state.check =
                        UPDATE(state.check, put - out, out)
                out = left
                if ((
                     REVERSE(hold)) != state.check):
                    state.mode = INFLATE_MODE.ACAB_BAD
                    break
                INITBITS()
                print("inflate:   check matches trailer\n")
            state.mode = INFLATE_MODE.DONE
        elif state.mode == INFLATE_MODE.DONE:
            ret = Z_STREAM_END
            """
               Return from inflate(), updating the total counts and the check value.
               If there was no progress during the inflate() call, return a buffer
               error.  Call updatewindow() to create and/or update the window state.
               Note: a memory error from inflate() is non-recoverable.
            """
            RESTORE()
            if (state.wsize or (state.mode < CHECK and out != strm.avail_out))
                if (updatewindow(strm, out)):
                    state.mode = INFLATE_MODE.MEM
                    return Z_MEM_ERROR
                }
            in_ -= strm.avail_in
            out -= strm.avail_out
            strm.total_in += in_
            strm.total_out += out
            state.total += out
            if (state.wrap and out)
                strm.adler = state.check = UPDATE(state.check, strm.next_out - out, out)
            strm.data_type = state.bits + (64 if state.last else 0) +
                              (128 if state.mode == INFLATE_MODE.TYPE else 0)
            if (((in == 0 and out == 0) or flush == Z_FINISH) and ret == Z_OK)
                ret = Z_BUF_ERROR
            return ret
        elif state.mode == INFLATE_MODE.ACAB_BAD:
            ret = Z_DATA_ERROR
            RESTORE()
            if (state.wsize or (state.mode < CHECK and out != strm.avail_out))
                if (updatewindow(strm, out)):
                    state.mode = INFLATE_MODE.MEM
                    return Z_MEM_ERROR
                }
            in_ -= strm.avail_in
            out -= strm.avail_out
            strm.total_in += in_
            strm.total_out += out
            state.total += out
            if (state.wrap and out)
                strm.adler = state.check = UPDATE(state.check, strm.next_out - out, out)
            strm.data_type = state.bits + (64 if state.last else 0) +
                              (128 if state.mode == INFLATE_MODE.TYPE else 0)
            if (((in == 0 and out == 0) or flush == Z_FINISH) and ret == Z_OK)
                ret = Z_BUF_ERROR
            return ret
        elif state.mode == INFLATE_MODE.MEM:
            return Z_MEM_ERROR
        elif state.mode == INFLATE_MODE.SYNC:
        else:
            return Z_STREAM_ERROR


def inflate64End(strm):
    if (strm == Z_NULL or strm.state == Z_NULL)
        return Z_STREAM_ERROR

    state = inflate_state()
    if (state.window != Z_NULL) free(state.window)
    free(strm.state)
    strm.state = Z_NULL
    print("inflate: end\n")
    return Z_OK


"""
   Build a set of tables to decode the provided canonical Huffman code.
   The code lengths are lens[0..codes-1].  The result starts at *table,
   whose indices are 0..2^bits-1.  work is a writable array of at least
   lens shorts, which is used as a work area.  type is the type of code
   to be generated, CODES, LENS, or DISTS.  On return, zero is success,
   -1 is an invalid code, and +1 means that ENOUGH isn't enough.  table
   on return points to the next available entry's address.  bits is the
   requested root table index bits, and on return it is the actual root
   table index bits.  It will differ if the request is greater than the
   longest code or if it is less than the shortest code.
 """
def inflate_table(type, lens, codes, table, bits, work):
    #  unsigned len               """ a code's length in bits """
    #  unsigned sym               """ index of code symbols """
    #  unsigned min, max          """ minimum and maximum code lengths """
    #  unsigned root              """ number of index bits for root table """
    #  unsigned curr              """ number of index bits for current table """
    #  unsigned drop              """ code bits to drop for sub-table """
    #  int left                   """ number of prefix codes available """
    #  unsigned used              """ code entries in table used """
    #  unsigned huff              """ Huffman code """
    #  unsigned incr              """ for incrementing code, index """
    #  unsigned fill              """ index for replicating entries """
    #  unsigned low               """ low bits for current root entry """
    #  unsigned mask              """ mask for low root bits """
    #  code this                  """ table entry for duplication """
    #  code FAR *next_             """ next available space in table """
    #  const unsigned short FAR *base     """ base value table to use """
    #  const unsigned short FAR *extra    """ extra bits table to use """
    #  int end                    """ use base and extra for symbol > end """
    #  unsigned short count[MAXBITS+1]    """ number of codes of each length """
    #  unsigned short offs[MAXBITS+1]     """ offsets in table for each length """
    #  static const unsigned short lbase[31] = { """ Length codes 257..285 base """
    """ Length codes 257..285 base """
    lbase = {
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227,
        """ 258 """
        3, 0, 0
    }
    static const unsigned short lext[31] = { """ Length codes 257..285 extra """
"""         16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, """
"""         19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 31, 201, 196} """
        128, 128, 128, 128, 128, 128, 128, 128, 129, 129, 129, 129, 130, 130, 130, 130,
        131, 131, 131, 131, 132, 132, 132, 132, 133, 133, 133, 133, 144, 201, 196}
    static const unsigned short dbase[32] = { """ Distance codes 0..29 base """
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
        8193, 12289, 16385, 24577, 32769, 49153}
    static const unsigned short dext[32] = { """ Distance codes 0..29 extra """
        16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22,
        23, 23, 24, 24, 25, 25, 26, 26, 27, 27,
        28, 28, 29, 29, 30, 30}

    """
       Process a set of code lengths to create a canonical Huffman code.  The
       code lengths are lens[0..codes-1].  Each length corresponds to the
       symbols 0..codes-1.  The Huffman code is generated by first sorting the
       symbols by length from short to long, and retaining the symbol order
       for codes with equal lengths.  Then the code starts with all zero bits
       for the first code of the shortest length, and the codes are integer
       increments for the same length, and zeros are appended as the length
       increases.  For the deflate format, these bits are stored backwards
       from their more natural integer increment ordering, and so when the
       decoding tables are built in the large loop below, the integer codes
       are incremented backwards.

       This routine assumes, but does not check, that all of the entries in
       lens[] are in the range 0..MAXBITS.  The caller must assure this.
       1..MAXBITS is interpreted as that code length.  zero means that that
       symbol does not occur in this code.

       The codes are sorted by computing a count of codes for each length,
       creating from that a table of starting indices for each length in the
       sorted table, and then entering the symbols in order in the sorted
       table.  The sorted table is work[], with that space being provided by
       the caller.

       The length counts are used for other purposes as well, i.e. finding
       the minimum and maximum length codes, determining if there are any
       codes at all, checking for a valid set of lengths, and looking ahead
       at length counts to determine sub-table sizes when building the
       decoding tables.
     """

    """ accumulate lengths for codes (assumes lens[] all in 0..MAXBITS) """
    for (len = 0 len <= MAXBITS len++)
        count[len] = 0
    for (sym = 0 sym < codes sym++)
        count[lens[sym]]++

    """ bound code lengths, force root to be within code lengths """
    root = *bits
    for (max = MAXBITS max >= 1 max--)
        if (count[max] != 0) break
    if (root > max) root = max
    if (max == 0):                     """ no symbols to code at all """
        this.op = (unsigned char)64    """ invalid code marker """
        this.bits = (unsigned char)1
        this.val = (unsigned short)0
        *(*table)++ = this             """ make a table to force an error """
        *(*table)++ = this
        *bits = 1
        return 0     """ no symbols, but wait for decoding to report error """
    }
    for (min = 1 min <= MAXBITS min++)
        if (count[min] != 0) break
    if (root < min) root = min

    """ check for an over-subscribed or incomplete set of lengths """
    left = 1
    for (len = 1 len <= MAXBITS len++):
        left <<= 1
        left -= count[len]
        if (left < 0) return -1        """ over-subscribed """
    }
    if (left > 0 and (type == CODES or max != 1))
        return -1                      """ incomplete set """

    """ generate offsets into symbol table for each length for sorting """
    offs[1] = 0
    for (len = 1 len < MAXBITS len++)
        offs[len + 1] = offs[len] + count[len]

    """ sort symbols by length, by symbol order within each length """
    for (sym = 0 sym < codes sym++)
        if (lens[sym] != 0) work[offs[lens[sym]]++] = (unsigned short)sym

    """
       Create and fill in decoding tables.  In this loop, the table being
       filled is at next and has curr index bits.  The code being used is huff
       with length len.  That code is converted to an index by dropping drop
       bits off of the bottom.  For codes where len is less than drop + curr,
       those top drop + curr - len bits are incremented through all values to
       fill the table with replicated entries.

       root is the number of index bits for the root table.  When len exceeds
       root, sub-tables are created pointed to by the root entry with an index
       of the low root bits of huff.  This is saved in low to check for when a
       new sub-table should be started.  drop is zero when the root table is
       being filled, and drop is root when sub-tables are being filled.

       When a new sub-table is needed, it is necessary to look ahead in the
       code lengths to determine what size sub-table is needed.  The length
       counts are used for this, and so count[] is decremented as codes are
       entered in the tables.

       used keeps track of how many table entries have been allocated from the
       provided *table space.  It is checked when a LENS table is being made
       against the space in *table, ENOUGH, minus the maximum space needed by
       the worst case distance code, MAXD.  This should never happen, but the
       sufficiency of ENOUGH has not been proven exhaustively, hence the check.
       This assumes that when type == LENS, bits == 9.

       sym increments through all symbols, and the loop terminates when
       all codes of length max, i.e. all codes, have been processed.  This
       routine permits incomplete codes, so another loop after this one fills
       in the rest of the decoding tables with invalid code markers.
     """

    """ set up for code type """
    if type == INFLATE_MODE.CODES:
        base = extra = work    """ dummy value--not used """
        end = 19
    elif type == INFLATE_MODE.LENS:
        base = lbase
        base -= 257
        extra = lext
        extra -= 257
        end = 256
    else:            """ DISTS """
        base = dbase
        extra = dext
        end = -1

    """ initialize state for loop """
    huff = 0                   """ starting code """
    sym = 0                    """ starting code symbol """
    len = min                  """ starting code length """
    next_ = *table              """ current table to fill in_ """
    curr = root                """ current table index bits """
    drop = 0                   """ current bits to drop from code for index """
    low = (-1)       """ trigger new sub-table when len > root """
    used = 1U << root          """ use root table entries """
    mask = used - 1            """ mask for comparing low """

    """ check available table space """
    if (type == LENS and used >= ENOUGH - MAXD)
        return 1

    """ process all codes and make table entries """
    while True:
        """ create table entry """
        this.bits = (unsigned char)(len - drop)
        if ((int)(work[sym]) < end):
            this.op = (unsigned char)0
            this.val = work[sym]
        elif ((int)(work[sym]) > end):
            this.op = (unsigned char)(extra[work[sym]])
            this.val = base[work[sym]]
        else:
            this.op = (unsigned char)(32 + 64)         """ end of block """
            this.val = 0

        """ replicate for those indices with low len bits equal to huff """
        incr = 1U << (len - drop)
        fill = 1U << curr
        min = fill                 """ save offset to next table """
        do:
            fill -= incr
            next[(huff >> drop) + fill] = this
        } while (fill != 0)

        """ backwards increment the len-bit code huff """
        incr = 1U << (len - 1)
        while (huff & incr)
            incr >>= 1
        if (incr != 0):
            huff &= incr - 1
            huff += incr
        else
            huff = 0

        """ go to next symbol, update count, len """
        sym++
        if (--(count[len]) == 0):
            if (len == max) break
            len = lens[work[sym]]
        }

        """ create new sub-table if needed """
        if (len > root and (huff & mask) != low):
            """ if first time, transition to sub-tables """
            if (drop == 0)
                drop = root

            """ increment past last table """
            next_ += min            """ here min is 1 << curr """

            """ determine length of next table """
            curr = len - drop
            left = (int)(1 << curr)
            while (curr + drop < max):
                left -= count[curr + drop]
                if (left <= 0) break
                curr++
                left <<= 1
            }

            """ check for enough space """
            used += 1U << curr
            if (type == LENS and used >= ENOUGH - MAXD)
                return 1

            """ point entry in root table to sub-table """
            low = huff & mask
            (*table)[low].op = (unsigned char)curr
            (*table)[low].bits = (unsigned char)root
            (*table)[low].val = (unsigned short)(next_ - *table)
        }
    }

    """
       Fill in rest of table for incomplete codes.  This loop is similar to the
       loop above in incrementing huff for table indices.  It is assumed that
       len is equal to curr + drop, so there is no loop needed to increment
       through high index bits.  When the current sub-table is filled, the loop
       drops back to the root table to fill in any remaining entries there.
     """
    this.op = (unsigned char)64                """ invalid code marker """
    this.bits = (unsigned char)(len - drop)
    this.val = (unsigned short)0
    while (huff != 0):
        """ when done with sub-table, drop back to root table """
        if (drop != 0 and (huff & mask) != low):
            drop = 0
            len = root
            next_ = *table
            this.bits = (unsigned char)len

        """ put invalid code marker in table """
        next[huff >> drop] = this

        """ backwards increment the len-bit code huff """
        incr = 1U << (len - 1)
        while (huff & incr)
            incr >>= 1
        if (incr != 0):
            huff &= incr - 1
            huff += incr
        else:
            huff = 0

    """ set return parameters """
    *table += used
    *bits = root
    return 0

