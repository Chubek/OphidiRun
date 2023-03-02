#include "../includes/slitherbrain.hpp"

namespace slitherbrain
{
    namespace http
    {
        string composeResponseLine(parseActonStat_t action_stat)
        {
            auto makeResp_f = [](const char *stat, string &resp_line)
            {
                stringstream strm;
                strm << VC;
                strm << ' ';
                strm << stat;
                strm << CRLF;

                resp_line = strm.str();
            };

            string resp_line;
            switch (action_stat)
            {
            case ParseEmptyRequest:
                makeResp_f(STATUS_BR, resp_line);
                break;
            case ParseWrongProtocol:
                makeResp_f(STATUS_UE, resp_line);
                break;
            case ParseWrongMethod:
                makeResp_f(STATUS_MNA, resp_line);
                break;
            case ParseWrongEndpont:
                makeResp_f(STATUS_NF, resp_line);
                break;
            case ParseWrongVC:
                makeResp_f(STATUS_UE, resp_line);
                break;
            case ParseBadCode:
                makeResp_f(STATUS_BR, resp_line);
                break;
            case ParseNoBody:
                makeResp_f(STATUS_BR, resp_line);
                break;
            case ParseReqLineOk:
                makeResp_f(STATUS_OK, resp_line);
                break;
            }

            return resp_line;
        }

        string composeResponseHeaders(size_t clen)
        {
            stringstream strm;

            strm << DATE_HN;
            strm << slitherbrain::utils::getCurrentUtcFormattedTime();
            strm << CRLF;

            strm << SERVER_NAME_HN;
            strm << SERVER_NAME;
            strm << CRLF;

            if (clen > 0)
            {
                strm << CONT_TYPE_HN;
                strm << CONT_TYPE;
                strm << CRLF;

                strm << CONT_LEN_HN;
                strm << clen;
                strm << CRLFX2;
            }

            return strm.str();
        }

        string composeResponse(parseActonStat_t action_state, string response_body)
        {
            string response_line = composeResponseLine(action_state);
            string response_headers = composeResponseHeaders(response_body.length());

            stringstream strm;

            strm << response_line;
            strm << response_headers;
            strm << response_body;

            return strm.str();
        }

        parseActonStat_t validateReqestLine(string requestLine)
        {
            vector<string> split = slitherbrain::strtools::splitStr(requestLine, " ");

            if (split.size() != 3)
                return ParseWrongProtocol;
            else if (split[0] != METHOD)
                return ParseWrongMethod;
            else if (!split[1].find(ENDPOINT_EXEC))
                return ParseWrongEndpont;
            else if (split[2] != VC)
                return ParseWrongVC;

            return ParseReqLineOk;
        }

        parseActonStat_t parseRequest(string request, string &code)
        {
            vector<string> request_split = slitherbrain::strtools::splitStr(request, CRLFX2);
            if (request_split.size() != 2)
            {
                return ParseNoBody;
            }

            code = request_split[1];
            vector<string> headers = slitherbrain::strtools::splitStr(request_split[0], CRLF);

            string checksum = getCheckSum(headers);
            if (!checkCodeIntegrity(code, checksum))
            {
                return ParseBadCode;
            }

            string req_line = headers[0];

            return validateReqestLine(req_line);
        }

        string getCheckSum(vector<string> headers)
        {
            string curr_line;
            for (int i = 0; i < headers.size(); i++)
            {
                curr_line = headers[i];
                slitherbrain::strtools::trimChar(curr_line, slitherbrain::consts::cTO_TRIM);

                if (curr_line.rfind(CHECKSUM_HN))
                {
                    curr_line.erase(0, string(CHECKSUM_HN).length());
                    slitherbrain::strtools::replaceChar(curr_line, QUOTE, NULLCHAR);
                }
            }

            return curr_line;
        }

        bool checkCodeIntegrity(string code, string checksum)
        {
            string hash = slitherbrain::pox::poxHash(code);

            return hash == checksum;
        }

    }
}