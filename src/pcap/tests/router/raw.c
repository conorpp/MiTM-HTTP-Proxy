#include "raw.h"

void SelectIPSocket(IPSocketList* list){
    struct timeval timeout = {0, 200 * 1000};
    FD_ZERO(&list->fdset);
    IPSocketNode* node = list->list;
    while(node != NULL){
        FD_SET(node->ipsock->sockfd, &list->fdset);
        node = node->next;
    }
    int ret = select(list->maxfd+1, &list->fdset,
                     NULL, NULL, &timeout);
    node = list->list;
    while(node != NULL){
        if (FD_ISSET(node->ipsock->sockfd, &list->fdset)){
            node->data_ready = 1;
            node->data_misses = 0;
        }else{
            node->data_ready = 0;
            node->data_misses++;
        }
        node = node->next;
    }
 
}


IPSocketList* getIPSocketList(){
    IPSocketList* list = malloc(sizeof(IPSocketList));
    if (list == (IPSocketList*)0){
        perror("malloc");
        exit(5);
    }
    memset(list, 0, sizeof(IPSocketList));
    return list;
}

IPSocketNode* getIPSocketNode(){
    IPSocketNode* node = malloc(sizeof(IPSocketNode));
    if (node == (IPSocketNode*)0){
        perror("malloc");
        exit(5);
    }
    memset(node, 0, sizeof(IPSocketNode));
    return node;
}
IPSocket* findIPSocket(IPSocketList* list, int num){
    IPSocketNode* node = list->list;
    while(node != NULL){
        if (node->i == num)
            return node->ipsock;
        node = node->next;
    }    
    return NULL;
}

void removeIPSocket(IPSocketList* listheader, IPSocketNode** node){
    IPSocketNode* list = listheader->list;
    IPSocketNode* before = NULL;
    while(list != NULL){
        if (list->i == (*node)->i){
            IPSocketNode* next = list->next;
            if (before == NULL){
                listheader->list = list->next;
            }else{
                before->next = next;
            }
            goto del;
        }
        before = list;
        list = list->next;    
    }
    return;
    del:
    (*node) = before;
    if (list->ipsock->sockfd == listheader->maxfd)
        listheader->maxfd--;
    freeRawSocket(list->ipsock);
    free(list);
    listheader->length--;
    if (before != NULL){
        while((before = before->next) != NULL){
            before->i--;
        }
    }
}

void freeIPSocketList(IPSocketList** list){
    if (list == (IPSocketList**)0) return;
    if (*list == (IPSocketList*)0) return;
    IPSocketNode* tmp = (*list)->list;
    IPSocketNode* del = (tmp);
    while(tmp->next != (IPSocketNode*)0){
        tmp = tmp->next;
        freeRawSocket(del->ipsock);
        free(del);
    }
    *list = NULL;
}

void addIPSocket(IPSocketList* listheader, IPSocket* ipsock){
    
    if (listheader->list == (IPSocketNode*)0)
        listheader->list = getIPSocketNode();
    
    IPSocketNode* list = listheader->list;
    
    if (list->ipsock == (IPSocket*)0){
        list->ipsock = ipsock;
        list->i = listheader->length;
        goto done;
    }
    while(list->next != (IPSocketNode*) 0)
        list = list->next;

    list->next = getIPSocketNode();
    list->next->ipsock = ipsock;
    list->next->i = listheader->length;

    done:
    listheader->length++;
    if (ipsock->sockfd > listheader->maxfd)
        listheader->maxfd = ipsock->sockfd;
}

void Bind(int fd, char* addr, int port){
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr (addr);

    int sl = sizeof(struct sockaddr_in);
    int ec = bind(fd, (struct sockaddr*)&sin, sl);

    if (ec != 0){
        perror("bind");
        exit(1);
    }
}


#define RAW_BIND (1 << 0)
IPSocket* getRawSocket(char* addr, int port, int proto, int flags){
   IPSocket* ipsock = malloc(sizeof(IPSocket));
   if (ipsock == (IPSocket*)0){
        perror("malloc");
        exit(5);
    }
    memset(ipsock, 0, sizeof(IPSocket));
    ipsock->sockfd = socket(PF_INET, SOCK_RAW, proto); 
    ipsock->proto = proto;
    ipsock->addr.sin_family = AF_INET;
    ipsock->addr.sin_port = port;
    ipsock->addr.sin_addr.s_addr = inet_addr(addr);
    ipsock->addr_size = sizeof(struct sockaddr_in);
    if (RAW_BIND & flags){
        Bind(ipsock->sockfd, addr, port);
    }
    return ipsock;
}
void freeRawSocket(IPSocket* ipsock){
    if (ipsock != (IPSocket*)0){
        int ec = close(ipsock->sockfd);
        if (ec != 0){
            perror("close");
            exit(1);
        }
        free(ipsock);
    }
}

int Recvfrom(IPSocket* ipsock, char* buf, int lim){
    return recvfrom(ipsock->sockfd,
                    buf, lim, 0,
                    (struct sockaddr*)&ipsock->addr,
                    (socklen_t*)&ipsock->addr_size);
}


int Sendto(IPSocket* ipsock, char* buf, int lim){
    return sendto(ipsock->sockfd, buf, lim, 0, 
            (struct sockaddr*)&ipsock->addr, ipsock->addr_size);
    
}
