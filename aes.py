import numpy as np
from functools import reduce
from itertools import chain
import copy

# Implements the AES standard for 16 byte intervals. No additional modes of operation are provided for
# data of size greater than 16 bytes.
class AES:
    def __init__(self, debug):
        self.expandedKeys = None
        self.debug = debug
        self.nb = 4
        self.sbox = [
            [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
            [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
            [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
            [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
            [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
            [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
            [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
            [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
            [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
            [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
            [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
            [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
            [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
            [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
            [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
            [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
        ];
        self.invSBox = [
            [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
            [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
            [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
            [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
            [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
            [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
            [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
            [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
            [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
            [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
            [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
            [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
            [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
            [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
            [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
            [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
        ];
        self.rcon = [0x00, 0x01, 0x02, 0x04, 0x08,
                     0x10, 0x20, 0x40, 0x80,
                     0x1B, 0x36, 0x6C, 0xD8,
                     0xAB, 0x4D, 0x9A, 0x2F,
                     0x5E, 0xBC, 0x63, 0xC6,
                     0x97, 0x35, 0x6A, 0xD4,
                     0xB3, 0x7D, 0xFA, 0xEF,
                     0xC5, 0x91, 0x39, 0x72,
                     0xE4, 0xD3, 0xBD, 0x61,
                     0xC2, 0x9F, 0x25, 0x4A,
                     0x94, 0x33, 0x66, 0xCC,
                     0x83, 0x1D, 0x3A, 0x74,
                     0xE8, 0xCB, 0x8D]

    # rotates a row by one
    def rotWord(self, a):
        return np.array([a[1], a[2], a[3], a[0]])

    # gets the rcon row for key expansion
    def getRcon(self, n):
        res =[self.rcon[int(n)], 0, 0, 0]
        return res

    # expands the given key into enough matrices for the number of rounds required by the keysize
    # nk is key length, nr is # rounds
    def keyExpansion(self, key, nk, nr):
        # expand enough key matrices for every round
        self.expandedKeys = np.zeros((4,4*(nr+1))).astype(int)
        self.expandedKeys[:,0:nk] = key[:,:]  # might need to make key a np matrix first?
        for i in range(nk,4*(nr+1)):
            temp = copy.deepcopy(self.expandedKeys[:,i-1]) # deepcopy required so earlier cols aren't modified
            if i % nk == 0:
                temp = self.rotWord(temp)
                temp = self._subBytesCol(temp)
                temp = temp ^ np.asarray(self.getRcon(i/nk))
            elif nk > 6 and i % nk == 4:
                temp = self._subBytesCol(temp)
            self.expandedKeys[:,i] = temp ^ self.expandedKeys[:,i-nk]


    # substitutes each state matrix byte with one in the sbox table
    def subBytes(self, state):
        for x in range(4):
            for y in range(4):
                state[x,y] = self._subByte(state[x, y])
        return state

    # substitutes each state matrix byte with one in the inverse sbox table
    def invSubBytes(self, state):
        for x in range(4):
            for y in range(4):
                state[x,y] = self._invSubByte(state[x, y])
        return state

    def _subByte(self, a):
        first = (a & 0xF0) >> 4
        second = a & 0x0F
        return self.sbox[first][second]

    def _invSubByte(self, a):
        first = (a & 0xF0) >> 4
        second = a & 0x0F
        return self.invSBox[first][second]

    # lazy implementation for substituting bytes from the sbox in just one column
    def _subBytesCol(self, state):
        for x in range(4):
            state[x] = self._subByte(state[x])
        return state

    # shifts each row in the matrix by a certain amount
    def shiftRows(self, state):
        res = [list(chain.from_iterable(np.array(state[0]).tolist())), [], [], []]
        for a in range(1,4):
            res[a] = list(chain.from_iterable(np.array(state[a,a:]).tolist() + np.array(state[a,:a]).tolist()))
        return np.matrix(res).astype(int)

    # shifts each row in the matrix by a certain amount, canceling out the original shiftRows encryption
    def invShiftRows(self, state):
        res = [list(chain.from_iterable(np.array(state[0]).tolist())), [], [], []]
        res[1] = list(chain.from_iterable(np.array(state[1,3:]).tolist() + np.array(state[1,:3]).tolist()))
        res[2] = list(chain.from_iterable(np.array(state[2,2:]).tolist() + np.array(state[2,:2]).tolist()))
        res[3] = list(chain.from_iterable(np.array(state[3,1:]).tolist() + np.array(state[3,:1]).tolist()))

        return np.matrix(res).astype(int)

    # adds using finite field (2^8) rules, which is XOR
    def ffAdd(self, a, b):
        return (a ^ b) & 0xFF

    # multiplies using finite field (2^8) rules
    def ffMultiply(self, a, b):
        # first takes care of LSB which has different rules
        cur = a
        xtimes = []
        res = 0
        for i in range(8):
            # calculate each xtime in case it will be used
            xtimes.append(cur)
            cur = self.xtime(cur)
            if b & 0x01:
                res =  res ^ xtimes[i]
            b = b >> 1
        return res

    # runs xtime() n iterations
    def xtime(self, p):
        ans = p << 1
        if ans & 0x100:
            ans = self.ffAdd(0x1b, ans)
        return ans

    # multiplies each column by a galois finite field matrix
    def mixColumns(self, state):
        res = np.matrix([[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]).astype(int)
        #galois matrix
        m = np.matrix([[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]])

        # alias function names for use below
        ffm = self.ffMultiply
        ffa = self.ffAdd

        colResult = np.zeros(4).astype(int)
        for y in range(4):
            col = state[:,y]
            for x in range(4):
                # calculate ffMultiply for each element in column
                ffmResults = [ffm(np.asscalar(col[i]),m[x,i]) for i in range(4)]
                # add all results together
                colResult[x] = reduce(lambda a,b : ffa(a,b), ffmResults)
            state[:,y] = np.reshape(colResult, (4,1))
        return state

    # multiplies each column by a different galois finite field matrix to get the inverse
    def invMixColumns(self, state):
        res = np.matrix([[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]).astype(int)
        #galois matrix to multiply by
        m = np.matrix([[0xe,0xb,0xd,0x9],[0x9,0xe,0xb,0xd],[0xd,0x9,0xe,0xb],[0xb,0xd,0x9,0xe]])

        # alias function names for use below
        ffm = self.ffMultiply
        ffa = self.ffAdd

        colResult = np.zeros(4).astype(int)
        for y in range(4):
            col = state[:,y]
            for x in range(4):
                # calculate ffMultiply for each element in column
                ffmResults = [ffm(np.asscalar(col[i]),m[x,i]) for i in range(4)]
                # add all results together
                colResult[x] = reduce(lambda a,b : ffa(a,b), ffmResults)
            state[:,y] = np.reshape(colResult, (4,1))
        return state


    # retrieves the correct 4x4 matrix from the key expansion
    def getKey(self, w, round):
        return self.expandedKeys[:, (round * 4) : (round * 4) + 4]

    # retrieves the correct key expansion matrix and XORs it with the state matrix
    def addRoundKey(self, w, round, state):
        res = np.mat(np.empty(shape=(4,4)).astype(int))
        roundKey = self.getKey(w, round)
        self._printState(roundKey, round, 'k_sch')
        for x in range(4):
            for y in range(4):
                res[x,y] = roundKey[x][y] ^ state[x,y]
        return res

    # retrieves the correct key expansion matrix and XORs it with the state matrix
    def invAddRoundKey(self, w, round, state, numRounds):
        res = np.mat(np.empty(shape=(4,4)).astype(int))
        roundKey = self.getKey(w, round)
        self._printState(roundKey, numRounds-round, 'ik_sc')
        for x in range(4):
            for y in range(4):
                res[x,y] = roundKey[x][y] ^ state[x,y]
        return res

    # returns the ciphertext for the given plaintext using the key
    def cipher(self, plaintext, key, keysize):

        if keysize == 128:
            numRounds = 10
            nk = 4
        elif keysize == 192:
            numRounds = 12
            nk = 6
        elif keysize == 256:
            numRounds = 14
            nk = 8
        else:
            raise Exception('Invalid size given')

        state = np.matrix(plaintext).astype(int)
        self._printState(state, 0, 'input')

        # completely expand keys before starting
        self.keyExpansion(np.matrix(key), nk, numRounds)
        state = self.addRoundKey(nk, 0, state)

        for round in range(1,numRounds+1):
            self._printState(state, round, 'start')
            state = self.subBytes(state)
            self._printState(state, round, 's_box')
            state = self.shiftRows(state)
            self._printState(state, round, 's_row')
            if round != numRounds:
                state = self.mixColumns(state)
                self._printState(state, round, 'm_col')
            state = self.addRoundKey(nk, round, state)

        self._printState(state, numRounds, 'out')
        print('\n')
        return state

    # returns the plaintext from the given ciphertext, using the key
    def invCipher(self, ciphertext, key, keysize):
        if keysize == 128:
            numRounds = 10
            nk = 4
        elif keysize == 192:
            numRounds = 12
            nk = 6
        elif keysize == 256:
            numRounds = 14
            nk = 8
        else:
            raise Exception('Invalid size given')

        state = np.matrix(ciphertext).astype(int)
        self._printState(state, 0, 'iinput')

        self.keyExpansion(np.matrix(key), nk, numRounds)
        state = self.invAddRoundKey(nk, numRounds, state, numRounds)

        for round in reversed(range(1,numRounds+1)):
            self._printState(state, numRounds-round+1, 'istar')
            state = self.invShiftRows(state)
            self._printState(state, numRounds-round+1, 'is_ro')
            state = self.invSubBytes(state)
            self._printState(state, numRounds-round+1, 'is_bo')
            state = self.invAddRoundKey(nk, round-1, state, numRounds)
            self._printState(state, numRounds-round+1, 'ik_ad')
            if round != 1:
                state = self.invMixColumns(state)
                # this printout is omitted in the spec
        self._printState(state, 0, 'iout')
        print('\n')
        return state


    # Utility methods

    # prints state of the aes block if in debug mode ONLY
    def _printState(self, state, round, type):
        if not self.debug:
            return
        stateSerialized = self.fromMatrix(state)
        print('r[' + str(round) + '].' + type + '\t\t' + stateSerialized)

    # converts a hexadecimal number to a matrix, defaulting to a 4x4 state matrix
    def toMatrix(self, bytes, size=16):
        m = [[], [], [], []]
        for n in range(size):
            m[n % 4].append((bytes >> ((size - n - 1) * 8)) & 0xFF)
        return m

    # converts a numpy matrix to a hexadecimal string representation
    def fromMatrix(self, m):
        if not isinstance(m, np.matrix):
            m = np.mat(m)

        bytes = list()
        for y in range(4):
            for x in range(4):
                bytes.append(format(m[x,y], '02x'))
        return ''.join(bytes)