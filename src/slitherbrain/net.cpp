#include "includes/slitherbrain.hpp"

namespace slitherbrain
{
    namespace net
    {
        sockAddrIn_t newSocketAddress(string ip, uint16_t port, netAddr_t addr_type)
        {
            int domain;
            if (addr_type == AddrTypeIPV4)
            {
                domain = AF_INET;
            }
            else
            {
                domain = AF_INET6;
            }

            sockAddrIn_t new_sock_addr;
            new_sock_addr.sin_family = domain;
            new_sock_addr.sin_port = port;

            inet_pton(domain, ip.c_str(), &new_sock_addr.sin_addr);

            return new_sock_addr;
        }

        int listenToSocket(sockAddrIn_t &socket_addr, netAddr_t addr_type)
        {
            int domain;
            if (addr_type == AddrTypeIPV4)
            {
                domain = AF_INET;
            }
            else
            {
                domain = AF_INET6;
            }

            int listener = socket(domain, SOCK_STREAM, 0);
            if (listener == -1)
            {
                ERR_EXIT("Problem occured with creating socket.");
            }

            if (bind(listener, (pSockAddr_t)&socket_addr, sizeof(socket_addr)) == -1)
            {
                ERR_EXIT("Problem occured with binding the socket");
            }

            if (listen(listener, SOMAXCONN) == -1)
            {
                ERR_EXIT("Problem occured with listening to the port");
            }

            return listener;
        }

        int accepetNewConnection(sockAddrIn_t &socket_addr, int listener)
        {
            socklen_t client_size = sizeof(socket_addr);
            int clientsock = accept(listener, (pSockAddr_t)&socket_addr, &client_size);

            return clientsock;
        }

        string readClientConnection(int clientsock)
        {
            char buff[BUFFSIZE];
            memset(buff, 0, BUFFSIZE);
            string readfully;

            int received = recv(clientsock, buff, BUFFSIZE, 0);
            while (received != 0 && received != -1)
            {
                readfully += string(buff);
                received = recv(clientsock, buff, BUFFSIZE, 0);
            }

            if (received == -1)
            {
                return NULL;
            }

            return readfully;
        }

        void readSocketExecuteAndSendBack(int clientsock, string slitherrun_path, string python_path, string disallowed_calls)
        {
            string request = readClientConnection(clientsock);
            string code;
            auto action_stat = slitherbrain::http::parseRequest(request, code);

            string resp_body;
            if (action_stat == slitherbrain::http::ParseReqLineOk)
            {
                resp_body = slitherbrain::process::runSlitherRunProcess(slitherrun_path, python_path, disallowed_calls, code);
            }
            else
            {
                resp_body = BODY_ERR;
            }

            auto response = composeResponse(action_stat, resp_body);
            send(clientsock, response.c_str(), response.length() + 1, 0);

            close(clientsock);
        }

        void serveHttpForever(string ip, int port, string slitherrun_path, string python_path, string disallowed_calls, volatile sig_atomic_t &sigc)
        {
            auto addr_type = getAddrType(ip);
            auto listener_addr = newSocketAddress(ip, port, addr_type);
            auto listener = listenToSocket(listener_addr, addr_type);

            while (!sigc)
            {
                sockAddrIn_t client_addr;
                int clientsocket = accepetNewConnection(client_addr, listener);
                if (!clientsocket)
                    continue;
                thread([clientsocket, slitherrun_path, python_path, disallowed_calls]()
                       { readSocketExecuteAndSendBack(clientsocket, slitherrun_path, python_path, disallowed_calls); });
            }

            close(listener);
        }

    }
}