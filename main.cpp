#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

# define PORT "3490"
# define BACKLOG 10
# define MAX_DATA_SIZE 65535

void sigchld_handler(int s) {
    auto saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


int main() {
    int sockfd, new_fd;
    ssize_t bytes_recv;
    struct addrinfo hints;
    struct addrinfo *adderinfo0;
    struct addrinfo *adderinfo;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;

    int yes = 1;
    char str_address[INET6_ADDRSTRLEN];
    char buffer[MAX_DATA_SIZE + 1];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int error = getaddrinfo(NULL, PORT, &hints, &adderinfo0);
    if (error) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        return 1;
    }

    for (adderinfo = adderinfo0; adderinfo ; adderinfo = adderinfo->ai_next) {
        sockfd = socket(adderinfo->ai_family, adderinfo->ai_socktype, adderinfo->ai_protocol);

        if (sockfd < 0) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
            perror("server: setsockopt");
            exit(1);
        }

        if (bind(sockfd, adderinfo->ai_addr, adderinfo->ai_addrlen) < 0) {
            close(sockfd);
            perror("sever: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(adderinfo0);

    if (adderinfo == NULL) {
        fprintf(stderr, "server: failed to bind");
    }

    if (listen(sockfd, BACKLOG) < 0) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);

    sa.sa_flags = SA_RESTART;

    if(sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while (1) {
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &sin_size);

        if (new_fd < 0) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *) &their_addr), str_address, sizeof(str_address));
        printf("server: got connection from %s\n", str_address);


        if (!fork()) {
            close(sockfd);

            size_t file_path_len = 0;
            long remaining_bytes = 0;

            if (recv(new_fd, &remaining_bytes, sizeof(long), 0) < 0) {
                perror("receive remaining bytes");
                close(new_fd);
                exit(0);
            }

            printf("File size: %ld\n", remaining_bytes);

            // We need to get the length from client first before start allocating the mem space
            if (recv(new_fd, &file_path_len, sizeof(size_t), 0) < 0) {
                perror("receive file path length");
                close(new_fd);
                exit(0);
            }

            printf("File path len: %d\n", (int)file_path_len);

            // Allocating the mem space for the filename string
            char * file_path = (char*)calloc(file_path_len + 1, sizeof(char));

            if (!file_path) {
                perror("Fail to allocate memory for filename");
                close(new_fd);
                exit(0);
            }

            // Waiting for client sending the file path in
            if ((bytes_recv = recv(new_fd, file_path, file_path_len, 0)) < 0) {
                perror("receive filename");
                close(new_fd);
                free(file_path);
                exit(0);
            }

            file_path[bytes_recv] = '\0';
            printf("Filename: %s\n", file_path);

            FILE *file = fopen(file_path, "w");

            if (!file) {
                perror("Write file");
                close(new_fd);
                free(file_path);
                exit(1);
            }

            while (remaining_bytes > 0) {
                if ((bytes_recv = recv(new_fd, buffer, MAX_DATA_SIZE, 0)) < 0) {
                    perror("send");
                    fclose(file);
                    close(new_fd);
                    exit(1);
                }

                if(bytes_recv > 0){
                    if (fwrite(buffer, sizeof(char), bytes_recv, file) < 0) {
                        perror("write");

                        fclose(file);
                        close(new_fd);
                        exit(1);
                    }

                    remaining_bytes -= bytes_recv;
                }
            }

            fclose(file);
            close(new_fd);
            exit(0);
        }

        close(new_fd);
    }
}