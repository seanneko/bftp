#!/usr/bin/python

import array
import math


class TabBits:
    def __init__(self, size, buffer=None, readFile=None):
        self.size = size
        self.num_bits_set = 0
        if buffer == None and readFile == None:
            size_buffer = int(math.ceil((size + 7) / 8))
            self._buffer = array.array('B')
            self._buffer.fromlist([0] * size_buffer)
        else:
            raise NotImplementedError

    def get(self, indexBit):
        indexOctet, decalage = divmod(indexBit, 8)
        octet = self._buffer[indexOctet]
        masque = 1 << decalage
        bit = octet & masque
        return bool(bit)

    def set(self, indexBit, valeur):
        valeur = bool(valeur)
        indexOctet, decalage = divmod(indexBit, 8)
        octet = self._buffer[indexOctet]
        masque = 1 << decalage
        ancienne_valeur = bool(octet & masque)
        if valeur == True and ancienne_valeur == False:
            octet = octet | masque
            self._buffer[indexOctet] = octet
            self.num_bits_set += 1
        elif valeur == False and ancienne_valeur == True:
            masque = 0xFF ^ masque
            octet = octet & masque
            self._buffer[indexOctet] = octet
            self.num_bits_set -= 1

    def __str__(self):
        chaine = ""
        for i in range(0, self.size):
            bit = self.get(i)
            if bit:
                chaine += "1"
            else:
                chaine += "0"
        return chaine


if __name__ == "__main__":
    N = 100
    tb = TabBits(N)
    print(str(tb))
    tb.set(2, True)
    tb.set(7, True)
    tb.set(N - 1, True)
    print(str(tb))
    print("tb[0] = %d" % tb.get(0))
    print("tb[2] = %d" % tb.get(2))
    print("tb[%d] = %d" % (N - 1, tb.get(N - 1)))
    print("size bits = %d" % tb.size)
    print("size buffer = %d" % len(tb._buffer))
