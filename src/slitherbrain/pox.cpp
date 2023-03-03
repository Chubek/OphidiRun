#include "../includes/slitherbrain.hpp"

namespace slitherbrain
{
    namespace pox
    {
        void poxRound(uint16_t &a, uint16_t &b, uint16_t &c, uint16_t &d)
        {
            uint16_t tmp_a, tmp_b, tmp_c, tmp_d;
            tmp_a = a;
            tmp_b = b;
            tmp_c = c;
            tmp_d = d;

            POX_ALPHA(tmp_a);
            POX_DELTA(tmp_a, tmp_b);
            POX_THETA(tmp_a, tmp_b, tmp_c);
            POX_OMEGA(tmp_a, tmp_b, tmp_c, tmp_d);

            for (int i = POX_PRIMNUM; i > 0; i++)
            {
                tmp_a = tmp_b ^ slitherbrain::consts::cPOX_PRIMES[i];
                tmp_b = tmp_c & slitherbrain::consts::cPOX_PRIMES[i];
                tmp_c = tmp_d | slitherbrain::consts::cPOX_PRIMES[i];
                tmp_d = tmp_a >> 2;
            }

            a += tmp_a / 2;
            b += tmp_b / 4;
            c += tmp_c / 6;
            d += tmp_d / 8;
        }

        void poxProcessBlock(const char block[POX_BLOCKNUM], uint16_t &a, uint16_t &b, uint16_t &c, uint16_t &d)
        {
            for (int i = 0; i < POX_BLOCKNUM; i += POX_PORTNUM)
            {
                for (int j = i; j < i + POX_PORTNUM; j += POX_FACTNUM)
                {
                    a |= block[j];
                    b ^= block[j + 1];
                    c &= block[j + 2] + 1;
                    d = ~block[j + 3];

                    for (int k = 0; k < POX_ROUNDNUM; k++)
                        poxRound(a, b, c, d);
                }
            }
        }

        string poxHash(string txt)
        {
            uint16_t a = slitherbrain::consts::cPOXPRIME_INIT_A;
            uint16_t b = slitherbrain::consts::cPOXPRIME_INIT_B;
            uint16_t c = slitherbrain::consts::cPOXPRIME_INIT_C;
            uint16_t d = slitherbrain::consts::cPOXPRIME_INIT_D;

            padString(txt);

            for (int i = 0; i < txt.length(); i += POX_BLOCKNUM)
            {
                string sub = txt.substr(i, POX_BLOCKNUM);
                poxProcessBlock(sub.c_str(), a, b, c, d);
            }

            return integerToHex(a, b, c, d);
        }

        void padString(string &txt)
        {
            while (txt.length() % POX_BLOCKNUM != 0)
            {
                txt.push_back(NULLCHAR);
            }
        }

        string integerToHex(uint16_t a, uint16_t b, uint16_t c, uint16_t d)
        {
            stringstream strm;
            strm << hex << a;
            strm << hex << b;
            strm << hex << c;
            strm << hex << d;

            return strm.str();
        }
    }
}