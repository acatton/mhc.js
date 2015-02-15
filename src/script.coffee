# (C) 2015-present Antoine Catton <devel at antoine dot catton dot fr>
#
# This file is part of mhc.js.
#
# mhc.js is a free software: you can redistribute it and/or modify it under the
# terms of the MIT License as published by the Open Source Initiative.
#
# mhc.js is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the MIT License for more details.
#
# You should have received a copy of the MIT License along with mhc.js. If not,
# see <http://opensource.org/licenses/MIT>.

BYTE_LENGTH = 8
ASCII_LEN = 7
ASCII_MASK = ( 1 << ASCII_LEN ) - 1
BASE_64 = 64

UTF8_MAX_BIT_AMOUNT = 31
UTF8_BYTE_BITS = 6
UTF8_BYTE_MASK = ( 1 << UTF8_BYTE_BITS ) - 1
UTF8_EXTRA_BITS = 0x80

uint8ArrayFrom = (arr) ->
    ret = new Uint8Array arr.length
    ret.set arr
    return ret

baseLog = (n, base) -> ( Math.log n ) / ( Math.log base )

utf8Encode = (val) ->
    countBits = (n) -> 1 + Math.floor baseLog n, 2

    bitsAmount = countBits val

    if bitsAmount <= ASCII_LEN
        [val]
    else
        if bitsAmount > UTF8_MAX_BIT_AMOUNT
            throw new Error(
                "UTF-8 doesn't support characters encoded on more than " +
                UTF8_MAX_BIT_AMOUNT + "bits"
            )

        byteAmount = 0
        bytes = []

        lastByteBitAmount = () -> BYTE_LENGTH - 2 - byteAmount
        lastByteExtraBits = () ->
            extraBits = (1 << byteAmount) - 1
            extraBits <<= 2
            extraBits |= 0x2
            extraBits <<= lastByteBitAmount()
            extraBits

        while countBits(val) > lastByteBitAmount()
            bytes.unshift ( val & UTF8_BYTE_MASK ) | UTF8_EXTRA_BITS
            val >>= UTF8_BYTE_BITS
            byteAmount++

        bytes.unshift ( val | lastByteExtraBits() )

        return bytes

strToUint8Array = (str) ->
    # TODO: Replace me by Uint8Array.from in Firefox 38
    uint8ArrayFrom str.split('').reduce (accumulator, element) ->
            accumulator.concat utf8Encode element.charCodeAt(0)
        , []

sha1Uint8Array = (arr) ->
    ( window.crypto.subtle.digest "SHA-1", arr.buffer ).then (result) ->
        new Uint8Array result

arrayToHex = (arr) ->
    toHex = (i) -> i.toString(16)
    reduce = (arr, callback, initialValue) ->
        acc = initialValue
        for i in [0..arr.length-1]
            acc = callback(acc, arr[i])
        return acc

    reduce arr, (accumulator, element) ->
            accumulator + if element > 16
                    toHex element
                else
                    "0" + toHex element
        , ""

HASHCASH_DEFAULT_VERSION = 1
HASHCASH_DEFAULT_BITS = 20  # This is a default recommended amount of bits
HASHCASH_DEFAULT_RAND_LEN = 16

hashcashDate = (d) ->
    toTwoNums = (n) ->
        n = n % 100
        if n < 10
            "0" + n
        else
            "" + n

    [d.getFullYear(), d.getMonth(), d.getHours(), d.getMinutes(),
     d.getSeconds()].reduce (accumulator, elem) ->
            accumulator + toTwoNums elem
        , ""

hashcashToString = (version, bits, date, resource, extension, rand, counter) ->
    version ?= HASHCASH_DEFAULT_VERSION
    bits ?= HASHCASH_DEFAULT_BITS

    date ?= new Date()
    date = if typeof date is "string" then date else hashcashDate date

    resource ?= ""
    extension ?= ""
    counter ?= ""

    return [version, bits, date, resource, extension, rand, counter].join ':'

intToBase64Char = (i) ->
    charOffset = (chr, offset) -> String.fromCharCode chr.charCodeAt(0) + offset

    if 0 <= i <= 25
        charOffset 'A', i
    else if 26 <= i <= 51
        charOffset 'a', i - 26
    else if 52 <= i <= 61
        charOffset '0', i - 52
    else if i == 62
        '+'
    else if i == 63
        '/'
    else
        throw new Error("intToBase64Char is supposed to get an ingeter " +
                        "between 0 and 63")

randomBase64String = (len) ->
    (intToBase64Char 0 | 63 * Math.random() for i in [1..len]).join ''

strToHexDigest = (str) ->
    (sha1Uint8Array strToUint8Array str).then (arr) -> arrayToHex arr

toResource = (val) ->
    # This is not cryptographically safe
    #
    # The goal of this function is to have a safe and stable string encoding
    # of a resource.

    hashKeyValue = (key, value) ->
        Promise.all([key, value].map toResource) \
            .then (resources) ->
                Promise.all resources.map strToHexDigest
            .then (digests) ->
                strToHexDigest digests.join ''

    hashArray = (arr) ->
        Promise.all( arr.map toResource ) \
            .then (resources) ->
                Promise.all( resources.map strToHexDigest )
            .then (hashes) ->
                hashes.sort()
                strToHexDigest hashes.join ''

    hashObject = (obj) ->
        Promise.all( hashKeyValue key, value for own key, value of obj \
                     when typeof value isnt "function" ) \
               .then (arr) -> hashArray arr

    stringToResource = (str) ->
        if str.match /:/
            strToHexDigest str
        else
            new Promise (resolve, reject) -> resolve str

    numberToResource = (n) -> new Promise (resolve, reject) -> resolve "" + n
    arrayToResource = (arr) -> hashArray arr
    objectToResource = (obj) -> hashObject obj

    if typeof val is "string"
        stringToResource val
    else if typeof val is "number"
        numberToResource val
    else if val.isArray
        arrayToResource val
    else if typeof val is "object"
        objectToResource val
    else
        throw new Error("toResource only supports strings, numbers and objects")

class window.Hashcash

    constructor: (str) ->
        [@version, @bits, @date, @resource, @extension, @rand, @counter] = \
            str.split(':')

        @bits ?= HASHCASH_DEFAULT_BITS
        @bits = @bits | 0

    toString: () ->
        hashcashToString @version, @bits, @date, @resource, @extension, @rand, \
            @counter

    findSolution: () ->
        stringOfCounter = (counter) -> ( counter.map intToBase64Char ).join ''

        hashcashStringOfCounter = (counter) =>
            hashcashToString @version, @bits, @date, @resource, @extension, \
                @rand, stringOfCounter counter

        isValid = (counter) =>
            str = hashcashStringOfCounter counter
            ( sha1Uint8Array strToUint8Array str ).then (result) =>
                ( uint8ArrayNullBitCount result ) >= @bits

        incrementCounter = (counter) ->
            for i, val of counter
                counter[i] = (val + 1) % BASE_64
                if counter[i] > 0
                    return counter

            counter.push 0
            return counter

        hashcashFromCounter = (counter) ->
            new Hashcash hashcashStringOfCounter counter


        new Promise (resolve, reject) ->
                counter = [0]

                check = (counter) ->
                    isValid(counter).then (counterIsValid) ->
                        if counterIsValid
                            resolve hashcashFromCounter counter
                        else
                            check incrementCounter counter

                check counter


window.Hashcash.fromResource = (resource) ->
    rand = randomBase64String HASHCASH_DEFAULT_RAND_LEN
    new Hashcash hashcashToString null, null, null, resource, null, rand, null


headNullBitCount = (n, length) ->
    if n == 0
        length
    else
        length - (1 + Math.floor baseLog n, 2)

uint8ArrayNullBitCount = (arr) ->
    acc = 0
    for i in [0..arr.length-1]
        value = arr[i]
        acc += headNullBitCount value, BYTE_LENGTH
        if value > 0
            break
    return acc
