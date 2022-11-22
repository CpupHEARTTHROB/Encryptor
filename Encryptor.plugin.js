/**
 * @name Encryptor
 * @author Cpup
 * @description Provides support for end-to-end encryption over private (one-on-one) channels.
 * @version 0.0.1
 */

 module.exports = class Encryptor {
    constructor(meta) {
        // Before starting
    }


    start() {

        /**
         * Container for AES
         */
        this.AES = AES;
        this.AES.Init();

        /**
         * Contianer for RSA
         */
        this.RSA = RSA;

        /**
         * Container for "to" functions
         */
        this.to = to;
        
    }    

    stop() {
        this.AES.Done();
    }
}

/**
 * Container for "to" functions
 */
var to = (function() {
    var my = {};

    my.cto = function(s, k) {
        return this.unpack(this.itob(AES.Encrypt(this.itoAES(this.stoi(s)), k))).join('');
    }

    my.cfrom = function(s, k) {
        return this.itos(this.AEStoi(AES.Decrypt(this.btoi(this.pack(s.split(''))), k)));
    }

    /**
     * String to int array
     * @param {string} msg - The message to be encrypted
     * @returns {Array<int>} Int-array version of msg
     */
     my.stoi = function(msg) {
        var out = [];
        for(var i = 0; i < msg.length; i++)
            out[i] = msg.charCodeAt(i);
        return out;
    }

    /**
     * Makes a fluffed hex string ready for AES encryption (packs automatically)
     * @param {Array<string>} iin 
     * @returns {Array<int>}
     */
    my.itoAES = function(iin) {
        var niin = AES.CopyArr(iin);
        for(; niin.length % 8 != 0; niin.push(0));
        var out = new Array(niin.length / 8);
        for(var i = 0; i < out.length; i++) {
            out[i] = [];
            for(var j = 0; j < 8; j++) {
                out[i].push(Math.floor(niin[i * 8 + j] / 256));
                out[i].push(niin[i * 8 + j] % 256);
            }
        }
        return out;
    }

    /**
     * Int to braillescript
     * @param {int} iarr 
     * @returns {string} 
     */
    my.itob = function(i) {
        var out;

        if(i instanceof Array) {
            out = [];
            for(var j of i)
                out.push(this.itob(j));
            return out;
        }

        out = "";
        for(var j = i; j >= 1; j /= 256) 
            out = String.fromCharCode(0x2800 + j % 256) + out;
        return out;
    }

    my.unpack = function(pin) {
        var out = [];
        for(var i of pin) {
            for(var j of i) {
                out.push(j);
            }
        }
        return out;
    }

    my.pack = function(ain) {
        var out = [];
        for(var i = 0; i < ain.length / 16; i++){
            out.push([]);
            for(var j = 0; j < 16; j++)
                out[i].push(ain[i * 16 + j]);
        }
        return out;
    }

    /**
     * Braillescript to int
     * @param {string} b
     * @returns {int} 
     */
    my.btoi = function(b) {
        var out;

        if(b instanceof Array) {
            out = [];
            for(var i of b)
                out.push(this.btoi(i));
            return out;
        }

        out = 0;
        for(var j = 0; j < b.length; j++)
            out = out * 256 + b.charCodeAt(j) - 0x2800;
        return out;
    }

    /**
     * Takes AES decryption output and turns it into hex strings
     * @param {Array<int>} AESin 
     * @returns {Array<string>}
     */
    my.AEStoi = function(AESin) {
        var out = [];
        for(var i = 0; i < AESin.length; i++) {;
            for(var j = 0; j < AESin[i].length / 2; j++)
                out.push(AESin[i][j * 2] * 256 + AESin[i][j * 2 + 1]);
        }
        return out;
    }
    
    /**
     * Opposite of stoi
     * @param {Array<int>} iarr - Int-array representation of original string
     * @returns {string} Original string
     */
    my.itos = function(iarr) {
        var out = "";
        for(var i = 0; i < iarr.length; i++)
            out += String.fromCharCode(iarr[i]);
        return out;
    }

    return my;
})();

var RSA = (function() {
    let my = {};

    /**
     * Generate an object containing a public and private key pair
     * @param {BigInt} public 
     * @param {BigInt} mod
     * @param {BigInt} private 
     * @returns 
     */
    my.KeyFactory = function(public, mod, private) {
        var key = {};
        key.public  = public;
        key.mod     = mod;
        key.private = private;
        return key;
    }

    my.gkpDEF = function() {
        return this.genKeyPair(this.genPrime(2048, 40), this.genPrime(2048, 40), 0);
    }

    my.genKeyPair = function(p, q, ein) {
        var n = q*p;
        var l = this.lcm(p - 1n, q - 1n);
        var e = (function(ein) {
            var e = (ein == 0n ? 2n**16n + 1n : ein);
            if(e > l) {
                e = BigInt(RSA.primeList[0]);
                for(var i = 0; RSA.gcd(e,l) != 1; e = BigInt(RSA.primeList[++i]));
            }
            for(; RSA.gcd(e, l) != 1; e = RSA.genPrime(2049, 40));
            return e;
        })(ein);
        var d = (function(a, m) {
            var m0 = m
            var y = 0n;
            var x = 1n;
            
            if(m == 1)
                return 0n;
            
            while(a > 1) {
                var q = a / m;
                var t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if(x < 0)
                x += m0;

            return x;
        })(e, l);
        return this.KeyFactory(e, n, d);
    }

    /**
     * Encrypts an array of ints
     * @param {Array<int>} iarr 
     * @param {BigInt} public
     * @param {BigInt} mod
     * @returns {Array<int>}
     */
    my.Encrypt = function(iarr, public, mod) {
        var out = new Array();
        for(var i of iarr)
            out.push(this.modpow(BigInt(i), public, mod));
        return out;
    }

    /**
     * Returns the inversely encrypted hash of a message array (its signature)
     * @param {Array<int>} msgarr 
     * @param {int} public 
     * @param {int} mod 
     * @returns {int}
     */
    my.msgSignature = function(msgarr, private, mod) {
        return this.modpow(to.htoi([this.hash(msgarr)]), private, mod);
    }

    /**
     * Decrypts an array of ints
     * @param {Array<int>} iarr 
     * @param {BigInt} private 
     * @param {BigInt} mod 
     * @returns {Array<int>}
     */
    my.Decrypt = function(iarr, private, mod) {
        var out = new Array();
        for(var i of iarr)
            out.push(this.modpow(BigInt(i), private, mod));
        return out;
    }

    /**
     * Memory-efficient modular exponentiation
     * @param {BigInt} b - Base 
     * @param {BigInt} e - Exponent
     * @param {BigInt} m - Modulus
     * @returns (b^e) % m
     */
    my.modpow = function(b, e, m) {
        b %= m;
        var r = 1n;
        var x = b;

        while(e > 0) {
            var lsb = e % 2n;
            e /= 2n;
            if(lsb == 1n) {
                r *= x;
                r %= m;
            }
            x *= x;
            x %= m;
        }

        return r;
    }

    /**
     * Least common multiple
     * @param {BigInt|int} first 
     * @param {BigInt|int} second
     * @return {BigInt|int} 
     */
    my.lcm = function(first, second) {
        return first * second / this.gcd(first, second);
    }

    /**
     * Greatest common demoninator
     * @param {BigInt|int} first 
     * @param {BigInt|int} second 
     * @returns {BigInt|int}
     */
    my.gcd = function(first, second) {
        if(first  == 0) return second;
        if(second == 0) return first;
        return first < second ? this.gcd(first, second % first) : this.gcd(first % second, second);
    }

    /**
     * Converts an integer array to a hash deterministically (TODO: MAKE MORE SECURE)
     * @param {Array<int>} iarr - Integer array
     * @return {string} Hash
     */
    my.hash = function(iarr) {
        var s = "";
        for(var i of iarr)
            s += String.fromCharCode(i);
        return SHA256(s);
    }

    /**
     * Generates a number that is likely prime
     * @param {BigInt} n - Number of bits
     * @param {?int} i - Iterations of the Miller Rabin Primality Test, the probability of the number not being prime is 1/4^i
     * -- set to 20 automatically
     * @return {BigInt} Likely prime
     */
    my.genPrime = function(n, i) {
        if(i == null) i = 20;
        var out = this.getLowLevelPrime(n);
        for(; !this.millerRabin(out, i); out = this.getLowLevelPrime(n));
        return out;
    }

    /**
     * Returns an n-bit random int
     * @param {int} n - Number of bits
     * @returns {BigInt} Random integer 
     */
    my.nBitRandom = function(n) {
        var out = 0n;
        for(var nn = n; nn >= 1; nn -= 32)
            out = out * 2n**BigInt(nn < 32 ? nn : 32) + BigInt(Math.floor(Math.seedrandom() * 2**(nn < 32 ? nn : 32)));
        return out;
    }

    // List of primes from 0 to 4000
    my.primeList = new Array(2, 3, 5, 7, 11, 13, 17, 19, 23, 29,31, 37, 41, 43, 47, 53, 59, 61, 67, 71,73, 79, 83, 89, 97, 101, 103, 107, 109, 113,127, 131, 137, 139, 149, 151, 157, 163, 167, 173,179, 181, 191, 193, 197, 199, 211, 223, 227, 229,233, 239, 241, 251, 257, 263, 269, 271, 277, 281,283, 293, 307, 311, 313, 317, 331, 337, 347, 349,353, 359, 367, 373, 379, 383, 389, 397, 401, 409,419, 421, 431, 433, 439, 443, 449, 457, 461, 463,467, 479, 487, 491, 499, 503, 509, 521, 523, 541,547, 557, 563, 569, 571, 577, 587, 593, 599, 601,607, 613, 617, 619, 631, 641, 643, 647, 653, 659,661, 673, 677, 683, 691, 701, 709, 719, 727, 733,739, 743, 751, 757, 761, 769, 773, 787, 797, 809,811, 821, 823, 827, 829, 839, 853, 857, 859, 863,877, 881, 883, 887, 907, 911, 919, 929, 937, 941,947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013,1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291,1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373,1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583,1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657,1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733,1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811,1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889,1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987,1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053,2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129,2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213,2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287,2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423,2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531,2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617,2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687,2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741,2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819,2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903,2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999,3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079,3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181,3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257,3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413,3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511,3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571,3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643,3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727,3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821,3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907,3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989,4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057,4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139,4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231,4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409,4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493,4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583,4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751,4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831,4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937,4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003,5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087,5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179,5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279,5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387,5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443,5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521,5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639,5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693,5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791,5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857,5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939,5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053,6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133,6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221,6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301,6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367,6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473,6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571,6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673,6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761,6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833,6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917,6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997,7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103,7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 720,7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297,7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411,7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499,7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561,7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643,7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723,7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829,7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919);

    /**
     * Returns an n-bit (somewhat likely) prime
     * @param {int} n - Number of bits
     * @returns {BigInt} Random (somewhat likely) prime
     */
    my.getLowLevelPrime = function(n) {
        var prime_candidate, bool = true;

        while(bool) {
            prime_candidate = this.nBitRandom(n);

            for(var divisor of this.primeList) {
                if(prime_candidate % BigInt(divisor) == 0 && prime_candidate >= divisor**2) {
                    bool = true;
                    break;
                }
                bool = false;
            }
        }
        return prime_candidate;
    }

    /**
     * Calculates (base ^ exp) % mod 
     * @param {BigInt} base
     * @param {BigInt} exp
     * @param {BigInt} mod
     * @return {BigInt}
     */
    my.expmod = function(base, exp, mod) {
        if(exp == 0n) return 1n;
        if(exp % 2n == 0n)
            return this.expmod(base, (exp / 2n), mod)**2n % mod;
        else
            return (base * this.expmod(base, (exp - 1n), mod)) % mod;
    }

    /**
     * Tests a Miller Rabin Primality candidate
     * @param {BigInt} candidate 
     * @param {int} interations
     * @return {boolean} True if it is prime
     */
    my.millerRabin = function(candidate, iterations) {
        var maxDivisionsByTwo = 0;
        var evenComponent = candidate - 1n;
        while(evenComponent % 2n == 0) {
            evenComponent >>= 1n;
            maxDivisionsByTwo++;
        }

        /**
         * @param {BigInt} round_tester 
         * @returns {boolean}
         */
        function trialComposite(round_tester) {
            if(my.expmod(round_tester, evenComponent, candidate) == 1)
                return false;
            for(var i = 0n; i < maxDivisionsByTwo; i++)
                if(my.expmod(round_tester, 2n**i * evenComponent, candidate) == candidate - 1n)
                    return false;
            return true;
        }

        for(var i = 0; i < iterations; i++) 
            if(trialComposite(BigInt(Math.floor(Math.seedrandom() * 2**32)) * (candidate - 2n) / 2n**32n + 2n))
                return false;

        return true;
    }
    return my;
})();


/*  CREDIT: wwwtryno @https://github.com/wwwtyro/cryptico/blob/master/aes.js
 *
 *  jsaes version 0.1  -  Copyright 2006 B. Poettering
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307 USA
 */
 
 // later modifications by wwwtyro@github

 // Comments by Cpup
 
 var AES = (function () {

    var my = {};

    /** 
     * Linearized AES Substitution Box -- see https://en.wikipedia.org/wiki/Rijndael_S-box
     */
    my.Sbox = new Array(99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22);

    /**
     * Linearized, transposing AES ShiftRow table
     */
    my.ShiftRowTab = new Array(0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11);
    
    /**
     * Initilizes my.Sbox_Inv, my.ShiftRowTab_Inv, and my.xtime
     */
    my.Init = function () {
        /**
         * Inverse of my.Sbox
         */
        my.Sbox_Inv = new Array(256);
        for (var i = 0; i < 256; i++)
            my.Sbox_Inv[my.Sbox[i]] = i;
        /**
         * Inverse of my.ShiftRowTab
         */
        my.ShiftRowTab_Inv = new Array(16);
        for (var i = 0; i < 16; i++)
            my.ShiftRowTab_Inv[my.ShiftRowTab[i]] = i;
        /**
         * Used in the MixColumns step
         */
        my.xtime = new Array(256);
        for (var i = 0; i < 128; i++) {
            my.xtime[i] = i << 1;
            my.xtime[128 + i] = (i << 1) ^ 0x1b; // = 27 (11011)
        }
    }

    /**
     * Delete arrays generated with my.Init
     */
    my.Done = function () {
        delete my.Sbox_Inv;
        delete my.ShiftRowTab_Inv;
        delete my.xtime;
    }

    /**
     * Creates a key schedule
     * @param {Array<int>} key - AES Key
     */
    my.ExpandKey = function (key) {
        var ckey = this.CopyArr(key);

        var kl = ckey.length,
            ks, Rcon = 1;
        switch (kl) {
        case 16:
            ks = 16 * (10 + 1); // = 1011 << 4 (10110000)
            break;
        case 24:
            ks = 16 * (12 + 1); // = 1101 << 4 (11010000)
            break;
        case 32:
            ks = 16 * (14 + 1); // = 1111 << 4 (11110000)
            break;
        default:
            alert("my.ExpandKey: Only key lengths of 16, 24 or 32 bytes allowed!");
        }
        for (var i = kl; i < ks; i += 4) {
            var temp = ckey.slice(i - 4, i);
            if (i % kl == 0) {
                temp = new Array(my.Sbox[temp[1]] ^ Rcon, my.Sbox[temp[2]], my.Sbox[temp[3]], my.Sbox[temp[0]]);
                if ((Rcon <<= 1) >= 256) Rcon ^= 0x11b; // = 283 (100011011)
            } else if ((kl > 24) && (i % kl == 16)) 
                temp = new Array(my.Sbox[temp[0]], my.Sbox[temp[1]], my.Sbox[temp[2]], my.Sbox[temp[3]]);
            for (var j = 0; j < 4; j++)
                ckey[i + j] = ckey[i + j - kl] ^ temp[j];
        }

        return ckey;
    }

    /**
     * Encrypts a block via AES using the AES Key
     * @param {Array<int>|Array<Array<int>>} block - Block to be encrypted (% 256)
     * @param {Array<int>} key - AES Key
     * @returns {Array<int>|Array<Array<int>>}
     */
    my.Encrypt = function (block, key) {
        var cblock = this.CopyArr(block);

        if(cblock[0] instanceof Array) {
            var out = [];
            for(var i of cblock)
                out.push(this.Encrypt(i, key));
            return out;
        }

        var l = key.length;
        my.AddRoundKey(cblock, key.slice(0, 16));
        for (var i = 16; i < l - 16; i += 16) {
            my.SubBytes(cblock, my.Sbox);
            my.ShiftRows(cblock, my.ShiftRowTab);
            my.MixColumns(cblock);
            my.AddRoundKey(cblock, key.slice(i, i + 16));
        }
        my.SubBytes(cblock, my.Sbox);
        my.ShiftRows(cblock, my.ShiftRowTab);
        my.AddRoundKey(cblock, key.slice(i, l));

        return cblock;
    }

    /**
     * Decrypts a block via AES using the AES Key
     * @param {Array<int>|Array<Array<int>>} block - Block to be decrypted (% 256)
     * @param {Array<int>} key - AES Key
     * @returns {Array<int>|Array<Array<int>>}
     */
    my.Decrypt = function (block, key) {
        var cblock = this.CopyArr(block);

        if(cblock[0] instanceof Array) {
            var out = [];
            for(var i of cblock)
                out.push(this.Decrypt(i, key));
            return out;
        }

        var l = key.length;
        my.AddRoundKey(cblock, key.slice(l - 16, l));
        my.ShiftRows(cblock, my.ShiftRowTab_Inv);
        my.SubBytes(cblock, my.Sbox_Inv);
        for (var i = l - 32; i >= 16; i -= 16) {
            my.AddRoundKey(cblock, key.slice(i, i + 16));
            my.MixColumns_Inv(cblock);
            my.ShiftRows(cblock, my.ShiftRowTab_Inv);
            my.SubBytes(cblock, my.Sbox_Inv);
        }
        my.AddRoundKey(cblock, key.slice(0, 16));

        return cblock;
    }

    /**
     * Replaces each byte in state with its entry in the substitution box
     * @param {Array<int>} state - Current block
     * @param {Array<int>} sbox - Substitution box
     */
    my.SubBytes = function (state, sbox) {
        for (var i = 0; i < 16; i++)
            state[i] = sbox[state[i]];
    }

    /**
     * Combines each byte of the state with the subkey (rkey)
     * @param {Array<int>} state - Current block
     * @param {Array<int>} rkey - Subkey (part of the AES Key)
     */
    my.AddRoundKey = function (state, rkey) {
        for (var i = 0; i < 16; i++)
            state[i] ^= rkey[i];
    }

    /**
     * Shifts Shifts each byte in state cyclically to the left
     * @param {Array<int>} state - Current block
     * @param {Array<int>} shifttab - Shift table
     */
    my.ShiftRows = function (state, shifttab) {
        var h = new Array().concat(state);
        for (var i = 0; i < 16; i++)
            state[i] = h[shifttab[i]];
    }

    /**
     * Multiplies each column with a fixed polynomial (xtime)
     * @param {Array<int>} state - Current block
     */
    my.MixColumns = function (state) {
        for (var i = 0; i < 16; i += 4) {
            var s0 = state[i + 0],
                s1 = state[i + 1];
            var s2 = state[i + 2],
                s3 = state[i + 3];
            var h = s0 ^ s1 ^ s2 ^ s3;
            state[i + 0] ^= h ^ my.xtime[s0 ^ s1];
            state[i + 1] ^= h ^ my.xtime[s1 ^ s2];
            state[i + 2] ^= h ^ my.xtime[s2 ^ s3];
            state[i + 3] ^= h ^ my.xtime[s3 ^ s0];
        }
    }

    /**
     * Inverses the mixcolumns step (using xtime)
     * @param {Array<int>} state - Current block
     */
    my.MixColumns_Inv = function (state) {
        for (var i = 0; i < 16; i += 4) {
            var s0 = state[i + 0],
                s1 = state[i + 1];
            var s2 = state[i + 2],
                s3 = state[i + 3];
            var h = s0 ^ s1 ^ s2 ^ s3;
            var xh = my.xtime[h];
            var h1 = my.xtime[my.xtime[xh ^ s0 ^ s2]] ^ h;
            var h2 = my.xtime[my.xtime[xh ^ s1 ^ s3]] ^ h;
            state[i + 0] ^= h1 ^ my.xtime[s0 ^ s1];
            state[i + 1] ^= h2 ^ my.xtime[s1 ^ s2];
            state[i + 2] ^= h1 ^ my.xtime[s2 ^ s3];
            state[i + 3] ^= h2 ^ my.xtime[s3 ^ s0];
        }
    }

    // Cpup additions
    my.genKey = function() {
        var key = new Array(32);
        for(var i = 0; i < key.length; i++)
            key[i] = Math.floor(Math.seedrandom() * 256);
        return key;
    }

    my.CopyArr = function(arr) {
        var out = [];
        for(var i of arr) {
            if(i instanceof Array)
                out.push(this.CopyArr(i));
            else
                out.push(i);
        }
        return arr
    }

    return my;

})();


// CREDIT wwwtryno @https://github.com/wwwtyro/cryptico/blob/master/random.js

// seedrandom.js version 2.0.
// Author: David Bau 4/2/2011
//
// Defines a method Math.seedrandom() that, when called, substitutes
// an explicitly seeded RC4-based algorithm for Math.random().  Also
// supports automatic seeding from local or network sources of entropy.
//
// Usage:
//
//   <script src=http://davidbau.com/encode/seedrandom-min.js></script>
//
//   Math.seedrandom('yipee'); Sets Math.random to a function that is
//                             initialized using the given explicit seed.
//
//   Math.seedrandom();        Sets Math.random to a function that is
//                             seeded using the current time, dom state,
//                             and other accumulated local entropy.
//                             The generated seed string is returned.
//
//   Math.seedrandom('yowza', true);
//                             Seeds using the given explicit seed mixed
//                             together with accumulated entropy.
//
//   <script src="http://bit.ly/srandom-512"></script>
//                             Seeds using physical random bits downloaded
//                             from random.org.
//
//   <script src="https://jsonlib.appspot.com/urandom?callback=Math.seedrandom">
//   </script>                 Seeds using urandom bits from call.jsonlib.com,
//                             which is faster than random.org.
//
// Examples:
//
//   Math.seedrandom("hello");            // Use "hello" as the seed.
//   document.write(Math.random());       // Always 0.5463663768140734
//   document.write(Math.random());       // Always 0.43973793770592234
//   var rng1 = Math.random;              // Remember the current prng.
//
//   var autoseed = Math.seedrandom();    // New prng with an automatic seed.
//   document.write(Math.random());       // Pretty much unpredictable.
//
//   Math.random = rng1;                  // Continue "hello" prng sequence.
//   document.write(Math.random());       // Always 0.554769432473455
//
//   Math.seedrandom(autoseed);           // Restart at the previous seed.
//   document.write(Math.random());       // Repeat the 'unpredictable' value.
//
// Notes:
//
// Each time seedrandom('arg') is called, entropy from the passed seed
// is accumulated in a pool to help generate future seeds for the
// zero-argument form of Math.seedrandom, so entropy can be injected over
// time by calling seedrandom with explicit data repeatedly.
//
// On speed - This javascript implementation of Math.random() is about
// 3-10x slower than the built-in Math.random() because it is not native
// code, but this is typically fast enough anyway.  Seeding is more expensive,
// especially if you use auto-seeding.  Some details (timings on Chrome 4):
//
// Our Math.random()            - avg less than 0.002 milliseconds per call
// seedrandom('explicit')       - avg less than 0.5 milliseconds per call
// seedrandom('explicit', true) - avg less than 2 milliseconds per call
// seedrandom()                 - avg about 38 milliseconds per call
//
// LICENSE (BSD):
//
// Copyright 2010 David Bau, all rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 
//   1. Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//   2. Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in the
//      documentation and/or other materials provided with the distribution.
// 
//   3. Neither the name of this module nor the names of its contributors may
//      be used to endorse or promote products derived from this software
//      without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
/**
 * All code is in an anonymous closure to keep the global namespace clean.
 *
 * @param {number=} overflow 
 * @param {number=} startdenom
 */
 (function (pool, math, width, chunks, significance, overflow, startdenom)
 {
 
 
     //
     // seedrandom()
     // This is the seedrandom function described above.
     //
     math['seedrandom'] = function seedrandom(seed, use_entropy)
     {
         var key = [];
         var arc4;
 
         // Flatten the seed string or build one from local entropy if needed.
         seed = mixkey(flatten(
         use_entropy ? [seed, pool] : arguments.length ? seed : [new Date().getTime(), pool, window], 3), key);
 
         // Use the seed to initialize an ARC4 generator.
         arc4 = new ARC4(key);
 
         // Mix the randomness into accumulated entropy.
         mixkey(arc4.S, pool);
 
         // Override Math.random
         // This function returns a random double in [0, 1) that contains
         // randomness in every bit of the mantissa of the IEEE 754 value.
         math['random'] = function random()
         { // Closure to return a random double:
             var n = arc4.g(chunks); // Start with a numerator n < 2 ^ 48
             var d = startdenom; //   and denominator d = 2 ^ 48.
             var x = 0; //   and no 'extra last byte'.
             while (n < significance)
             { // Fill up all significant digits by
                 n = (n + x) * width; //   shifting numerator and
                 d *= width; //   denominator and generating a
                 x = arc4.g(1); //   new least-significant-byte.
             }
             while (n >= overflow)
             { // To avoid rounding up, before adding
                 n /= 2; //   last byte, shift everything
                 d /= 2; //   right using integer math until
                 x >>>= 1; //   we have exactly the desired bits.
             }
             return (n + x) / d; // Form the number within [0, 1).
         };
 
         // Return the seed that was used
         return seed;
     };
 
     //
     // ARC4
     //
     // An ARC4 implementation.  The constructor takes a key in the form of
     // an array of at most (width) integers that should be 0 <= x < (width).
     //
     // The g(count) method returns a pseudorandom integer that concatenates
     // the next (count) outputs from ARC4.  Its return value is a number x
     // that is in the range 0 <= x < (width ^ count).
     //
     /** @constructor */
 
     function ARC4(key)
     {
         var t, u, me = this,
             keylen = key.length;
         var i = 0,
             j = me.i = me.j = me.m = 0;
         me.S = [];
         me.c = [];
 
         // The empty key [] is treated as [0].
         if (!keylen)
         {
             key = [keylen++];
         }
 
         // Set up S using the standard key scheduling algorithm.
         while (i < width)
         {
             me.S[i] = i++;
         }
         for (i = 0; i < width; i++)
         {
             t = me.S[i];
             j = lowbits(j + t + key[i % keylen]);
             u = me.S[j];
             me.S[i] = u;
             me.S[j] = t;
         }
 
         // The "g" method returns the next (count) outputs as one number.
         me.g = function getnext(count)
         {
             var s = me.S;
             var i = lowbits(me.i + 1);
             var t = s[i];
             var j = lowbits(me.j + t);
             var u = s[j];
             s[i] = u;
             s[j] = t;
             var r = s[lowbits(t + u)];
             while (--count)
             {
                 i = lowbits(i + 1);
                 t = s[i];
                 j = lowbits(j + t);
                 u = s[j];
                 s[i] = u;
                 s[j] = t;
                 r = r * width + s[lowbits(t + u)];
             }
             me.i = i;
             me.j = j;
             return r;
         };
         // For robust unpredictability discard an initial batch of values.
         // See http://www.rsa.com/rsalabs/node.asp?id=2009
         me.g(width);
     }
 
     //
     // flatten()
     // Converts an object tree to nested arrays of strings.
     //
     /** @param {Object=} result 
      * @param {string=} prop
      * @param {string=} typ */
 
     function flatten(obj, depth, result, prop, typ)
     {
         result = [];
         typ = typeof (obj);
         if (depth && typ == 'object')
         {
             for (prop in obj)
             {
                 if (prop.indexOf('S') < 5)
                 { // Avoid FF3 bug (local/sessionStorage)
                     try
                     {
                         result.push(flatten(obj[prop], depth - 1));
                     }
                     catch (e)
                     {}
                 }
             }
         }
         return (result.length ? result : obj + (typ != 'string' ? '\0' : ''));
     }
 
     //
     // mixkey()
     // Mixes a string seed into a key that is an array of integers, and
     // returns a shortened string seed that is equivalent to the result key.
     //
     /** @param {number=} smear 
      * @param {number=} j */
 
     function mixkey(seed, key, smear, j)
     {
         seed += ''; // Ensure the seed is a string
         smear = 0;
         for (j = 0; j < seed.length; j++)
         {
             key[lowbits(j)] = lowbits((smear ^= key[lowbits(j)] * 19) + seed.charCodeAt(j));
         }
         seed = '';
         for (j in key)
         {
             seed += String.fromCharCode(key[j]);
         }
         return seed;
     }
 
     //
     // lowbits()
     // A quick "n mod width" for width a power of 2.
     //
 
 
     function lowbits(n)
     {
         return n & (width - 1);
     }
 
     //
     // The following constants are related to IEEE 754 limits.
     //
     startdenom = math.pow(width, chunks);
     significance = math.pow(2, significance);
     overflow = significance * 2;
 
     //
     // When seedrandom.js is loaded, we immediately mix a few bits
     // from the built-in RNG into the entropy pool.  Because we do
     // not want to intefere with determinstic PRNG state later,
     // seedrandom will not call math.random on its own again after
     // initialization.
     //
     mixkey(math.random(), pool);
 
     // End anonymous scope, and pass initial values.
 })([], // pool: entropy pool starts empty
 Math, // math: package containing random, pow, and seedrandom
 256, // width: each RC4 output is 0 <= x < 256
 6, // chunks: at least six RC4 outputs for each double
 52 // significance: there are 52 significant digits in a double
 );
 
 
 // This is not really a random number generator object, and two SeededRandom
 // objects will conflict with one another, but it's good enough for generating 
 // the rsa key.
 function SeededRandom(){}
 
 function SRnextBytes(ba)
 {
     var i;
     for(i = 0; i < ba.length; i++)
     {
         ba[i] = Math.floor(Math.random() * 256);
     }
 }
 
 SeededRandom.prototype.nextBytes = SRnextBytes;
 
 // prng4.js - uses Arcfour as a PRNG
 
 function Arcfour() {
   this.i = 0;
   this.j = 0;
   this.S = new Array();
 }
 
 // Initialize arcfour context from key, an array of ints, each from [0..255]
 function ARC4init(key) {
   var i, j, t;
   for(i = 0; i < 256; ++i)
     this.S[i] = i;
   j = 0;
   for(i = 0; i < 256; ++i) {
     j = (j + this.S[i] + key[i % key.length]) & 255;
     t = this.S[i];
     this.S[i] = this.S[j];
     this.S[j] = t;
   }
   this.i = 0;
   this.j = 0;
 }
 
 function ARC4next() {
   var t;
   this.i = (this.i + 1) & 255;
   this.j = (this.j + this.S[this.i]) & 255;
   t = this.S[this.i];
   this.S[this.i] = this.S[this.j];
   this.S[this.j] = t;
   return this.S[(t + this.S[this.i]) & 255];
 }
 
 Arcfour.prototype.init = ARC4init;
 Arcfour.prototype.next = ARC4next;
 
 // Plug in your RNG constructor here
 function prng_newstate() {
   return new Arcfour();
 }
 
 // Pool size must be a multiple of 4 and greater than 32.
 // An array of bytes the size of the pool will be passed to init()
 var rng_psize = 256;
 
 // Random number generator - requires a PRNG backend, e.g. prng4.js
 
 // For best results, put code like
 // <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
 // in your main HTML document.
 
 var rng_state;
 var rng_pool;
 var rng_pptr;
 
 // Mix in a 32-bit integer into the pool
 function rng_seed_int(x) {
   rng_pool[rng_pptr++] ^= x & 255;
   rng_pool[rng_pptr++] ^= (x >> 8) & 255;
   rng_pool[rng_pptr++] ^= (x >> 16) & 255;
   rng_pool[rng_pptr++] ^= (x >> 24) & 255;
   if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
 }
 
 // Mix in the current time (w/milliseconds) into the pool
 function rng_seed_time() {
   rng_seed_int(new Date().getTime());
 }
 
 // Initialize the pool with junk if needed.
 if(rng_pool == null) {
   rng_pool = new Array();
   rng_pptr = 0;
   var t;
   if(navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
     // Extract entropy (256 bits) from NS4 RNG if available
     var z = window.crypto.random(32);
     for(t = 0; t < z.length; ++t)
       rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
   }  
   while(rng_pptr < rng_psize) {  // extract some randomness from Math.random()
     t = Math.floor(65536 * Math.random());
     rng_pool[rng_pptr++] = t >>> 8;
     rng_pool[rng_pptr++] = t & 255;
   }
   rng_pptr = 0;
   rng_seed_time();
   //rng_seed_int(window.screenX);
   //rng_seed_int(window.screenY);
 }
 
 function rng_get_byte() {
   if(rng_state == null) {
     rng_seed_time();
     rng_state = prng_newstate();
     rng_state.init(rng_pool);
     for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
       rng_pool[rng_pptr] = 0;
     rng_pptr = 0;
     //rng_pool = null;
   }
   // TODO: allow reseeding after first request
   return rng_state.next();
 }
 
 function rng_get_bytes(ba) {
   var i;
   for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
 }
 
 function SecureRandom() {}
 
 SecureRandom.prototype.nextBytes = rng_get_bytes; 


/**
*
*  Secure Hash Algorithm (SHA256)
*  http://www.webtoolkit.info/
*
*  Original code by Angel Marin, Paul Johnston.
*
**/
 
function SHA256(s){
 
	var chrsz   = 8;
	var hexcase = 0;
 
	function safe_add (x, y) {
		var lsw = (x & 0xFFFF) + (y & 0xFFFF);
		var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
		return (msw << 16) | (lsw & 0xFFFF);
	}
 
	function S (X, n) { return ( X >>> n ) | (X << (32 - n)); }
	function R (X, n) { return ( X >>> n ); }
	function Ch(x, y, z) { return ((x & y) ^ ((~x) & z)); }
	function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }
	function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
	function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
	function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
	function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }
 
	function core_sha256 (m, l) {
		var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);
		var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
		var W = new Array(64);
		var a, b, c, d, e, f, g, h, i, j;
		var T1, T2;
 
		m[l >> 5] |= 0x80 << (24 - l % 32);
		m[((l + 64 >> 9) << 4) + 15] = l;
 
		for ( var i = 0; i<m.length; i+=16 ) {
			a = HASH[0];
			b = HASH[1];
			c = HASH[2];
			d = HASH[3];
			e = HASH[4];
			f = HASH[5];
			g = HASH[6];
			h = HASH[7];
 
			for ( var j = 0; j<64; j++) {
				if (j < 16) W[j] = m[j + i];
				else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
 
				T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
				T2 = safe_add(Sigma0256(a), Maj(a, b, c));
 
				h = g;
				g = f;
				f = e;
				e = safe_add(d, T1);
				d = c;
				c = b;
				b = a;
				a = safe_add(T1, T2);
			}
 
			HASH[0] = safe_add(a, HASH[0]);
			HASH[1] = safe_add(b, HASH[1]);
			HASH[2] = safe_add(c, HASH[2]);
			HASH[3] = safe_add(d, HASH[3]);
			HASH[4] = safe_add(e, HASH[4]);
			HASH[5] = safe_add(f, HASH[5]);
			HASH[6] = safe_add(g, HASH[6]);
			HASH[7] = safe_add(h, HASH[7]);
		}
		return HASH;
	}
 
	function str2binb (str) {
		var bin = Array();
		var mask = (1 << chrsz) - 1;
		for(var i = 0; i < str.length * chrsz; i += chrsz) {
			bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i%32);
		}
		return bin;
	}
 
	function Utf8Encode(string) {
		string = string.replace(/\r\n/g,"\n");
		var utftext = "";
 
		for (var n = 0; n < string.length; n++) {
 
			var c = string.charCodeAt(n);
 
			if (c < 128) {
				utftext += String.fromCharCode(c);
			}
			else if((c > 127) && (c < 2048)) {
				utftext += String.fromCharCode((c >> 6) | 192);
				utftext += String.fromCharCode((c & 63) | 128);
			}
			else {
				utftext += String.fromCharCode((c >> 12) | 224);
				utftext += String.fromCharCode(((c >> 6) & 63) | 128);
				utftext += String.fromCharCode((c & 63) | 128);
			}
 
		}
 
		return utftext;
	}
 
	function binb2hex (binarray) {
		var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
		var str = "";
		for(var i = 0; i < binarray.length * 4; i++) {
			str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
			hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
		}
		return str;
	}
 
	s = Utf8Encode(s);
	return binb2hex(core_sha256(str2binb(s), s.length * chrsz));
}

var sha256 = {}
sha256.hex = function(s)
{
    return SHA256(s);
}

/**
*
*  Secure Hash Algorithm (SHA1)
*  http://www.webtoolkit.info/
*
**/
 
function SHA1 (msg) {
 
	function rotate_left(n,s) {
		var t4 = ( n<<s ) | (n>>>(32-s));
		return t4;
	};
 
	function lsb_hex(val) {
		var str="";
		var i;
		var vh;
		var vl;
 
		for( i=0; i<=6; i+=2 ) {
			vh = (val>>>(i*4+4))&0x0f;
			vl = (val>>>(i*4))&0x0f;
			str += vh.toString(16) + vl.toString(16);
		}
		return str;
	};
 
	function cvt_hex(val) {
		var str="";
		var i;
		var v;
 
		for( i=7; i>=0; i-- ) {
			v = (val>>>(i*4))&0x0f;
			str += v.toString(16);
		}
		return str;
	};
 
 
	function Utf8Encode(string) {
		string = string.replace(/\r\n/g,"\n");
		var utftext = "";
 
		for (var n = 0; n < string.length; n++) {
 
			var c = string.charCodeAt(n);
 
			if (c < 128) {
				utftext += String.fromCharCode(c);
			}
			else if((c > 127) && (c < 2048)) {
				utftext += String.fromCharCode((c >> 6) | 192);
				utftext += String.fromCharCode((c & 63) | 128);
			}
			else {
				utftext += String.fromCharCode((c >> 12) | 224);
				utftext += String.fromCharCode(((c >> 6) & 63) | 128);
				utftext += String.fromCharCode((c & 63) | 128);
			}
 
		}
 
		return utftext;
	};
 
	var blockstart;
	var i, j;
	var W = new Array(80);
	var H0 = 0x67452301;
	var H1 = 0xEFCDAB89;
	var H2 = 0x98BADCFE;
	var H3 = 0x10325476;
	var H4 = 0xC3D2E1F0;
	var A, B, C, D, E;
	var temp;
 
	msg = Utf8Encode(msg);
 
	var msg_len = msg.length;
 
	var word_array = new Array();
	for( i=0; i<msg_len-3; i+=4 ) {
		j = msg.charCodeAt(i)<<24 | msg.charCodeAt(i+1)<<16 |
		msg.charCodeAt(i+2)<<8 | msg.charCodeAt(i+3);
		word_array.push( j );
	}
 
	switch( msg_len % 4 ) {
		case 0:
			i = 0x080000000;
		break;
		case 1:
			i = msg.charCodeAt(msg_len-1)<<24 | 0x0800000;
		break;
 
		case 2:
			i = msg.charCodeAt(msg_len-2)<<24 | msg.charCodeAt(msg_len-1)<<16 | 0x08000;
		break;
 
		case 3:
			i = msg.charCodeAt(msg_len-3)<<24 | msg.charCodeAt(msg_len-2)<<16 | msg.charCodeAt(msg_len-1)<<8	| 0x80;
		break;
	}
 
	word_array.push( i );
 
	while( (word_array.length % 16) != 14 ) word_array.push( 0 );
 
	word_array.push( msg_len>>>29 );
	word_array.push( (msg_len<<3)&0x0ffffffff );
 
 
	for ( blockstart=0; blockstart<word_array.length; blockstart+=16 ) {
 
		for( i=0; i<16; i++ ) W[i] = word_array[blockstart+i];
		for( i=16; i<=79; i++ ) W[i] = rotate_left(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
 
		A = H0;
		B = H1;
		C = H2;
		D = H3;
		E = H4;
 
		for( i= 0; i<=19; i++ ) {
			temp = (rotate_left(A,5) + ((B&C) | (~B&D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
			E = D;
			D = C;
			C = rotate_left(B,30);
			B = A;
			A = temp;
		}
 
		for( i=20; i<=39; i++ ) {
			temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
			E = D;
			D = C;
			C = rotate_left(B,30);
			B = A;
			A = temp;
		}
 
		for( i=40; i<=59; i++ ) {
			temp = (rotate_left(A,5) + ((B&C) | (B&D) | (C&D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
			E = D;
			D = C;
			C = rotate_left(B,30);
			B = A;
			A = temp;
		}
 
		for( i=60; i<=79; i++ ) {
			temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
			E = D;
			D = C;
			C = rotate_left(B,30);
			B = A;
			A = temp;
		}
 
		H0 = (H0 + A) & 0x0ffffffff;
		H1 = (H1 + B) & 0x0ffffffff;
		H2 = (H2 + C) & 0x0ffffffff;
		H3 = (H3 + D) & 0x0ffffffff;
		H4 = (H4 + E) & 0x0ffffffff;
 
	}
 
	var temp = cvt_hex(H0) + cvt_hex(H1) + cvt_hex(H2) + cvt_hex(H3) + cvt_hex(H4);
 
	return temp.toLowerCase();
 
}

var sha1 = {}
sha1.hex = function(s)
{
    return SHA1(s);
}

/**
*
*  MD5 (Message-Digest Algorithm)
*  http://www.webtoolkit.info/
*
**/
 
var MD5 = function (string) {
 
	function RotateLeft(lValue, iShiftBits) {
		return (lValue<<iShiftBits) | (lValue>>>(32-iShiftBits));
	}
 
	function AddUnsigned(lX,lY) {
		var lX4,lY4,lX8,lY8,lResult;
		lX8 = (lX & 0x80000000);
		lY8 = (lY & 0x80000000);
		lX4 = (lX & 0x40000000);
		lY4 = (lY & 0x40000000);
		lResult = (lX & 0x3FFFFFFF)+(lY & 0x3FFFFFFF);
		if (lX4 & lY4) {
			return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
		}
		if (lX4 | lY4) {
			if (lResult & 0x40000000) {
				return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
			} else {
				return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
			}
		} else {
			return (lResult ^ lX8 ^ lY8);
		}
 	}
 
 	function F(x,y,z) { return (x & y) | ((~x) & z); }
 	function G(x,y,z) { return (x & z) | (y & (~z)); }
 	function H(x,y,z) { return (x ^ y ^ z); }
	function I(x,y,z) { return (y ^ (x | (~z))); }
 
	function FF(a,b,c,d,x,s,ac) {
		a = AddUnsigned(a, AddUnsigned(AddUnsigned(F(b, c, d), x), ac));
		return AddUnsigned(RotateLeft(a, s), b);
	};
 
	function GG(a,b,c,d,x,s,ac) {
		a = AddUnsigned(a, AddUnsigned(AddUnsigned(G(b, c, d), x), ac));
		return AddUnsigned(RotateLeft(a, s), b);
	};
 
	function HH(a,b,c,d,x,s,ac) {
		a = AddUnsigned(a, AddUnsigned(AddUnsigned(H(b, c, d), x), ac));
		return AddUnsigned(RotateLeft(a, s), b);
	};
 
	function II(a,b,c,d,x,s,ac) {
		a = AddUnsigned(a, AddUnsigned(AddUnsigned(I(b, c, d), x), ac));
		return AddUnsigned(RotateLeft(a, s), b);
	};
 
	function ConvertToWordArray(string) {
		var lWordCount;
		var lMessageLength = string.length;
		var lNumberOfWords_temp1=lMessageLength + 8;
		var lNumberOfWords_temp2=(lNumberOfWords_temp1-(lNumberOfWords_temp1 % 64))/64;
		var lNumberOfWords = (lNumberOfWords_temp2+1)*16;
		var lWordArray=Array(lNumberOfWords-1);
		var lBytePosition = 0;
		var lByteCount = 0;
		while ( lByteCount < lMessageLength ) {
			lWordCount = (lByteCount-(lByteCount % 4))/4;
			lBytePosition = (lByteCount % 4)*8;
			lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount)<<lBytePosition));
			lByteCount++;
		}
		lWordCount = (lByteCount-(lByteCount % 4))/4;
		lBytePosition = (lByteCount % 4)*8;
		lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80<<lBytePosition);
		lWordArray[lNumberOfWords-2] = lMessageLength<<3;
		lWordArray[lNumberOfWords-1] = lMessageLength>>>29;
		return lWordArray;
	};
 
	function WordToHex(lValue) {
		var WordToHexValue="",WordToHexValue_temp="",lByte,lCount;
		for (lCount = 0;lCount<=3;lCount++) {
			lByte = (lValue>>>(lCount*8)) & 255;
			WordToHexValue_temp = "0" + lByte.toString(16);
			WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length-2,2);
		}
		return WordToHexValue;
	};
 
	function Utf8Encode(string) {
		string = string.replace(/\r\n/g,"\n");
		var utftext = "";
 
		for (var n = 0; n < string.length; n++) {
 
			var c = string.charCodeAt(n);
 
			if (c < 128) {
				utftext += String.fromCharCode(c);
			}
			else if((c > 127) && (c < 2048)) {
				utftext += String.fromCharCode((c >> 6) | 192);
				utftext += String.fromCharCode((c & 63) | 128);
			}
			else {
				utftext += String.fromCharCode((c >> 12) | 224);
				utftext += String.fromCharCode(((c >> 6) & 63) | 128);
				utftext += String.fromCharCode((c & 63) | 128);
			}
 
		}
 
		return utftext;
	};
 
	var x=Array();
	var k,AA,BB,CC,DD,a,b,c,d;
	var S11=7, S12=12, S13=17, S14=22;
	var S21=5, S22=9 , S23=14, S24=20;
	var S31=4, S32=11, S33=16, S34=23;
	var S41=6, S42=10, S43=15, S44=21;
 
	string = Utf8Encode(string);
 
	x = ConvertToWordArray(string);
 
	a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;
 
	for (k=0;k<x.length;k+=16) {
		AA=a; BB=b; CC=c; DD=d;
		a=FF(a,b,c,d,x[k+0], S11,0xD76AA478);
		d=FF(d,a,b,c,x[k+1], S12,0xE8C7B756);
		c=FF(c,d,a,b,x[k+2], S13,0x242070DB);
		b=FF(b,c,d,a,x[k+3], S14,0xC1BDCEEE);
		a=FF(a,b,c,d,x[k+4], S11,0xF57C0FAF);
		d=FF(d,a,b,c,x[k+5], S12,0x4787C62A);
		c=FF(c,d,a,b,x[k+6], S13,0xA8304613);
		b=FF(b,c,d,a,x[k+7], S14,0xFD469501);
		a=FF(a,b,c,d,x[k+8], S11,0x698098D8);
		d=FF(d,a,b,c,x[k+9], S12,0x8B44F7AF);
		c=FF(c,d,a,b,x[k+10],S13,0xFFFF5BB1);
		b=FF(b,c,d,a,x[k+11],S14,0x895CD7BE);
		a=FF(a,b,c,d,x[k+12],S11,0x6B901122);
		d=FF(d,a,b,c,x[k+13],S12,0xFD987193);
		c=FF(c,d,a,b,x[k+14],S13,0xA679438E);
		b=FF(b,c,d,a,x[k+15],S14,0x49B40821);
		a=GG(a,b,c,d,x[k+1], S21,0xF61E2562);
		d=GG(d,a,b,c,x[k+6], S22,0xC040B340);
		c=GG(c,d,a,b,x[k+11],S23,0x265E5A51);
		b=GG(b,c,d,a,x[k+0], S24,0xE9B6C7AA);
		a=GG(a,b,c,d,x[k+5], S21,0xD62F105D);
		d=GG(d,a,b,c,x[k+10],S22,0x2441453);
		c=GG(c,d,a,b,x[k+15],S23,0xD8A1E681);
		b=GG(b,c,d,a,x[k+4], S24,0xE7D3FBC8);
		a=GG(a,b,c,d,x[k+9], S21,0x21E1CDE6);
		d=GG(d,a,b,c,x[k+14],S22,0xC33707D6);
		c=GG(c,d,a,b,x[k+3], S23,0xF4D50D87);
		b=GG(b,c,d,a,x[k+8], S24,0x455A14ED);
		a=GG(a,b,c,d,x[k+13],S21,0xA9E3E905);
		d=GG(d,a,b,c,x[k+2], S22,0xFCEFA3F8);
		c=GG(c,d,a,b,x[k+7], S23,0x676F02D9);
		b=GG(b,c,d,a,x[k+12],S24,0x8D2A4C8A);
		a=HH(a,b,c,d,x[k+5], S31,0xFFFA3942);
		d=HH(d,a,b,c,x[k+8], S32,0x8771F681);
		c=HH(c,d,a,b,x[k+11],S33,0x6D9D6122);
		b=HH(b,c,d,a,x[k+14],S34,0xFDE5380C);
		a=HH(a,b,c,d,x[k+1], S31,0xA4BEEA44);
		d=HH(d,a,b,c,x[k+4], S32,0x4BDECFA9);
		c=HH(c,d,a,b,x[k+7], S33,0xF6BB4B60);
		b=HH(b,c,d,a,x[k+10],S34,0xBEBFBC70);
		a=HH(a,b,c,d,x[k+13],S31,0x289B7EC6);
		d=HH(d,a,b,c,x[k+0], S32,0xEAA127FA);
		c=HH(c,d,a,b,x[k+3], S33,0xD4EF3085);
		b=HH(b,c,d,a,x[k+6], S34,0x4881D05);
		a=HH(a,b,c,d,x[k+9], S31,0xD9D4D039);
		d=HH(d,a,b,c,x[k+12],S32,0xE6DB99E5);
		c=HH(c,d,a,b,x[k+15],S33,0x1FA27CF8);
		b=HH(b,c,d,a,x[k+2], S34,0xC4AC5665);
		a=II(a,b,c,d,x[k+0], S41,0xF4292244);
		d=II(d,a,b,c,x[k+7], S42,0x432AFF97);
		c=II(c,d,a,b,x[k+14],S43,0xAB9423A7);
		b=II(b,c,d,a,x[k+5], S44,0xFC93A039);
		a=II(a,b,c,d,x[k+12],S41,0x655B59C3);
		d=II(d,a,b,c,x[k+3], S42,0x8F0CCC92);
		c=II(c,d,a,b,x[k+10],S43,0xFFEFF47D);
		b=II(b,c,d,a,x[k+1], S44,0x85845DD1);
		a=II(a,b,c,d,x[k+8], S41,0x6FA87E4F);
		d=II(d,a,b,c,x[k+15],S42,0xFE2CE6E0);
		c=II(c,d,a,b,x[k+6], S43,0xA3014314);
		b=II(b,c,d,a,x[k+13],S44,0x4E0811A1);
		a=II(a,b,c,d,x[k+4], S41,0xF7537E82);
		d=II(d,a,b,c,x[k+11],S42,0xBD3AF235);
		c=II(c,d,a,b,x[k+2], S43,0x2AD7D2BB);
		b=II(b,c,d,a,x[k+9], S44,0xEB86D391);
		a=AddUnsigned(a,AA);
		b=AddUnsigned(b,BB);
		c=AddUnsigned(c,CC);
		d=AddUnsigned(d,DD);
	}
 
	var temp = WordToHex(a)+WordToHex(b)+WordToHex(c)+WordToHex(d);
 
	return temp.toLowerCase();
}