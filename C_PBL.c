#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

#define MAX_USERS 1000
#define MAX_LINE 2048

typedef struct UserData{
    char username[50];
    char password[65];
    char public_key[16];
    char public_key_hash[65];
    double balance;
    double loan;
    double credit;
    double debit;
} UserData;

//function prototypes for ritesh's part
void sha256_hash_str(const char *str, char out_hex[65]);
int load_users(UserData users[], int max_users, const char *filename);
int save_users(UserData users[], int count, const char *filename);
void append_transaction_record(const char *sender, const char *receiver, double amount, const char *nonce, const char *sig_hash, const char *receiver_pubkey, const char *type);
int find_user_index(UserData users[], int count, const char *username);
void generate_random_bytes_hex(char *out_hex, size_t hex_len);
void generate_unique_public_key(UserData users[], int count, char *out_pk, int digits);
int mine_signature_prefix(const char *pubkey_hash, int difficulty, char *out_nonce, char *out_mined_hash);
void add_or_regenerate_public_key(const char *dbfile);
void send_money(const char *dbfile);
void request_money(const char *dbfile);
void request_draft_menu(const char *dbfile, const char *current_user);
void view_transaction_history(const char *dbfile, const char *current_user);

//function prototypes for dwij's modified parts
void new_user(const char *dbfile);
void displayUser(const char *dbfile, const char *username, const char *password, int *flag);

//function prototypes for adhayan's modified parts
void Menu();
void update_balance_and_record(const char *dbfile, const char *username, double amount, const char *type);


int main() {
    const char *dbfile = "SDF_PBL-databbase.csv";
    char userh[10];
    char username[50];
    char password[128];
    int choice, count = 0;
    float transactions[100];
    char type[100][12];
    char cont[5];
    int continue_transaction = 1;
    start:
    int flag = 1;
    printf("\n\n");
    printf("============================================================\n");   
    printf("                     Encrypted Banking                      \n");
    printf("============================================================\n");
    printf("                          Welcome!                          \n\n");

    printf("Are you a new user or existing user? (new/old): ");
    scanf("%9s", userh);
    if (strcmp(userh, "new") == 0) {
        new_user(dbfile);
        goto start;
    } else if (strcmp(userh, "old") == 0) {
        printf("\nEnter your username: ");
        scanf("%49s", username);
        printf("Enter your password: ");
        scanf("%127s", password);
        displayUser(dbfile, username, password, &flag);
        if (!flag)
        {
            goto start;
        }
    } else {
        printf("Invalid input.\n");
        goto start;
    }
    do {
        Menu();
        printf("Enter your choice: ");
        scanf("%d", &choice);
        double amount;
        switch (choice) {
            case 1:
                printf("Enter amount to deposit: ");
                scanf("%lf", &amount);
                update_balance_and_record(dbfile, username, amount, "Deposit");
                break;

            case 2:
                printf("Enter amount to withdraw: ");
                scanf("%lf", &amount);
                update_balance_and_record(dbfile, username, amount, "Withdraw");
                break;

            case 3:
                view_transaction_history(dbfile, username);
                break;
            case 4:
                send_money(dbfile);
                break;
            case 5:
                add_or_regenerate_public_key(dbfile);
                break;
            case 6:
                request_money(dbfile);
                break;

            case 7:
                request_draft_menu(dbfile, username);
                break;

            case 8:
                continue_transaction = 0;
                break;
            default:
                printf("Invalid option.\n");
        }
        if (continue_transaction) {
            do {
                printf("Do you want to perform another transaction? (yes/no): ");
                scanf("%4s", cont);
                if (strcmp(cont, "yes") == 0 || strcmp(cont, "YES") == 0) { continue_transaction = 1; break; }
                if (strcmp(cont, "no") == 0 || strcmp(cont, "NO") == 0) { continue_transaction = 0; break; }
                printf("Invalid input.\n");
            } while (1);
        }
    } while (continue_transaction);
    return 0;
}

//ritesh's part of code
void sha256_hash_str(const char *str, char out_hex[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)str, strlen(str), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) sprintf(out_hex + (i*2), "%02x", hash[i]);
    out_hex[64] = 0;
}

int load_users(UserData users[], int max_users, const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return 0;
    char line[MAX_LINE];
    int count = 0;
    if (!fgets(line, sizeof(line), f)) { 
        fclose(f); 
        return 0; 
    }
    while (fgets(line, sizeof(line), f) && count < max_users) {
        line[strcspn(line, "\r\n")] = 0;
        char *p = line;
        char *token = strtok(p, ",");
        while (token && strlen(token) == 0) token = strtok(NULL, ",");

        if (!token) continue;
        strncpy(users[count].username, token, sizeof(users[count].username)-1);
        users[count].username[sizeof(users[count].username)-1] = '\0';
        token = strtok(NULL, ",");

        if (!token) continue;
        strncpy(users[count].password, token, sizeof(users[count].password)-1);
        users[count].password[sizeof(users[count].password)-1] = '\0';
        token = strtok(NULL, ",");

        if (!token) continue;
        strncpy(users[count].public_key, token, sizeof(users[count].public_key)-1);
        users[count].public_key[sizeof(users[count].public_key)-1] = '\0';
        token = strtok(NULL, ",");

        if (!token) continue;
        strncpy(users[count].public_key_hash, token, sizeof(users[count].public_key_hash)-1);
        users[count].public_key_hash[sizeof(users[count].public_key_hash)-1] = '\0';
        token = strtok(NULL, ",");
        users[count].balance = token ? atof(token) : 0.0;
        token = strtok(NULL, ",");
        users[count].loan = token ? atof(token) : 0.0;
        token = strtok(NULL, ",");
        users[count].credit = token ? atof(token) : 0.0;
        token = strtok(NULL, ",");
        users[count].debit = token ? atof(token) : 0.0;
        ++count;
    }
    fclose(f);
    return count;
}

int save_users(UserData users[], int count, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) return 0;
    fprintf(f, "username,password_hash,public_key,public_key_hash,balance,loan,credit,debit\n");
    for (int i = 0; i < count; ++i) {
        fprintf(f, "%s,%s,%s,%s,%.2lf,%.2lf,%.2lf,%.2lf\n",
            users[i].username,
            users[i].password,
            users[i].public_key,
            users[i].public_key_hash,
            users[i].balance,
            users[i].loan,
            users[i].credit,
            users[i].debit
        );
    }
    fclose(f);
    return 1;
}

void append_transaction_record(const char *sender, const char *receiver, double amount, const char *nonce, const char *sig_hash, const char *receiver_pubkey, const char *type) {
    FILE *f = fopen("transactions.csv", "a");
    if (!f) {
        f = fopen("transactions.csv", "w");
        if (!f) 
        {
            return;
        }
        fprintf(f, "sender,receiver,amount,nonce,signature_hash,receiver_public_key,timestamp\n");
    }
    time_t t = time(NULL);
    fprintf(f, "%s,%s,%.2lf,%s,%s,%s,%ld, %s\n", sender, receiver, amount, nonce, sig_hash, receiver_pubkey, (long)t, type);
    fclose(f);
}

void view_transaction_history(const char *dbfile, const char *current_user) {
    FILE *f = fopen(dbfile, "r");
    if (!f) {
        printf("Database not found.\n");
        return;
    }

    char line[512];
    fgets(line, sizeof(line), f);

    int found = 0;
    char uname[50], pass_hash[100], pubkey[50], pubkey_hash[100];
    char balance[50], loan[50], credit[50], debit[50];

    while (fgets(line, sizeof(line), f)) {
        char u[50], ph[100], pk[50], pkh[100];
        char bal[50], ln[50], cr[50], dbt[50];

        int fields = sscanf(line,
            "%49[^,],%99[^,],%49[^,],%99[^,],%49[^,],%49[^,],%49[^,],%49[^,\n]",
            u, ph, pk, pkh, bal, ln, cr, dbt);

        if (fields == 8 && strcmp(u, current_user) == 0) {
            strcpy(uname, u);
            strcpy(pass_hash, ph);
            strcpy(pubkey, pk);
            strcpy(pubkey_hash, pkh);
            strcpy(balance, bal);
            strcpy(loan, ln);
            strcpy(credit, cr);
            strcpy(debit, dbt);
            found = 1;
            break;
        }
    }

    fclose(f);

    if (!found) {
        printf("User not found in database.\n");
        return;
    }

    printf("\nUSER DETAILS\n");
    printf("Username: %s\n", uname);
    printf("Password Hash: %s\n", pass_hash);
    printf("Public Key: %s\n", pubkey);
    printf("Public Key Hash: %s\n", pubkey_hash);
    printf("Balance: %s\n", balance);
    printf("Loan: %s\n", loan);
    printf("Credit: %s\n", credit);
    printf("Debit: %s\n\n", debit);

    FILE *t = fopen("transactions.csv", "r");
    if (!t) {
        printf("No transactions found.\n");
        return;
    }

    fgets(line, sizeof(line), t);
    int shown = 0;

    printf("TRANSACTION HISTORY\n\n");

    while (fgets(line, sizeof(line), t)) {
        char user[50], other[50], amount[50], nonce[50];
        char sig[100], txid[100], timestamp[50], type[50];

        int fields = sscanf(line,
            "%49[^,],%49[^,],%49[^,],%49[^,],%99[^,],%99[^,],%49[^,],%49[^,\n]",
            user, other, amount, nonce, sig, txid, timestamp, type);

        if (fields == 8 && strcmp(user, current_user) == 0) {
            printf("Type: %s\n", type);
            printf("Amount: %s\n", amount);
            printf("Other Party: %s\n", other);
            printf("Timestamp: %s\n", timestamp);
            printf("Transaction ID: %s\n", txid);
            printf("\n");
            shown = 1;
        }
    }

    fclose(t);

    if (!shown)
        printf("No transactions available for this user.\n");
}


int find_user_index(UserData users[], int count, const char *username) {
    for (int i = 0; i < count; ++i) if (strcmp(users[i].username, username) == 0) return i;
    return -1;
}

void generate_random_bytes_hex(char *out_hex, size_t hex_len) {
    if (hex_len > 64)
    { 
    hex_len = 64;
    }
    size_t bytes = hex_len / 2;
    srand((unsigned int)time(NULL) ^ (unsigned int)rand());
    for (size_t i = 0; i < bytes; ++i) {
        unsigned int b = rand() & 0xFF;
        sprintf(out_hex + (i*2), "%02x", b);
    }
    out_hex[hex_len] = 0;
}

void generate_unique_public_key(UserData users[], int count, char *out_pk, int digits) {
    int min = 1;
    for (int i = 1; i < digits; ++i) min *= 10;
    int max = 1;
    for (int i = 0; i < digits; ++i) max *= 10;
    srand((unsigned int)time(NULL) ^ (unsigned int)rand());
    int tries = 0;
    while (1) {
        int candidate = (rand() % (max - min)) + min;
        char cand_str[16];
        snprintf(cand_str, sizeof(cand_str), "%d", candidate);
        int ok = 1;
        for (int i = 0; i < count; ++i) if (strcmp(users[i].public_key, cand_str) == 0) { 
            ok = 0; 
            break; 
        }
        if (ok) { 
            strncpy(out_pk, cand_str, 15); 
            out_pk[15] = '\0'; 
            return; 
        }
        if (++tries > 100000) { 
            snprintf(out_pk, 16, "%d", (min + (rand() % (max-min)))); 
            return; 
        }
    }
}

int mine_signature_prefix(const char *pubkey_hash, int difficulty, char *out_nonce, char *out_mined_hash) {
    if (difficulty < 1) difficulty = 1;
    if (difficulty > 60) difficulty = 60;
    char target_prefix[65];
    for (int i = 0; i < difficulty; ++i) target_prefix[i] = '0';
    target_prefix[difficulty] = 0;
    unsigned long long counter = 0;
    char candidate_nonce[129];
    char buf[1024];
    char h[65];
    while (counter < 0xFFFFFFFFULL) {
        unsigned long long r = ((unsigned long long)rand() << 32) ^ ((unsigned long long)rand() << 16) ^ (unsigned long long)rand() ^ counter ^ (unsigned long long)time(NULL);
        snprintf(candidate_nonce, sizeof(candidate_nonce), "%016llx", r);
        snprintf(buf, sizeof(buf), "%s%s", pubkey_hash, candidate_nonce);
        sha256_hash_str(buf, h);
        if (strncmp(h, target_prefix, difficulty) == 0) {
            strncpy(out_nonce, candidate_nonce, 128);
            out_nonce[128] = '\0';
            strncpy(out_mined_hash, h, 64);
            out_mined_hash[64] = '\0';
            return 1;
        }
        ++counter;
        if ((counter & 0xFFFFF) == 0xFFFFF) srand((unsigned int)time(NULL) ^ (unsigned int)counter);
    }
    strncpy(out_nonce, candidate_nonce, 128);
    out_nonce[128] = '\0';
    strncpy(out_mined_hash, h, 64);
    out_mined_hash[64] = '\0';
    return 0;
}

void add_or_regenerate_public_key(const char *dbfile) {
    UserData users[MAX_USERS];
    int ucount = load_users(users, MAX_USERS, dbfile);
    if (ucount < 0) return;
    char username[50];
    printf("Enter username to add/regenerate public key: ");
    scanf("%49s", username);
    int idx = find_user_index(users, ucount, username);
    if (idx == -1) { 
        printf("User not found.\n"); 
        return; 
    }
    char new_pk[16];
    generate_unique_public_key(users, ucount, new_pk, 6);
    char pk_hash[65];
    sha256_hash_str(new_pk, pk_hash);
    strncpy(users[idx].public_key, new_pk, sizeof(users[idx].public_key)-1);
    users[idx].public_key[sizeof(users[idx].public_key)-1] = '\0';
    strncpy(users[idx].public_key_hash, pk_hash, sizeof(users[idx].public_key_hash)-1);
    users[idx].public_key_hash[sizeof(users[idx].public_key_hash)-1] = '\0';
    if (!save_users(users, ucount, dbfile)) { 
        printf("Failed to save database.\n"); 
        return; 
    }
    printf("Public key assigned to user %s: %s\n", users[idx].username, users[idx].public_key);
    printf("Store this public key securely; it is shown only now.\n");
}

void send_money(const char *dbfile) {
    UserData users[MAX_USERS];
    int ucount = load_users(users, MAX_USERS, dbfile);
    if (ucount <= 0) { 
        printf("No users loaded or database missing.\n"); 
        return; 
    }
    char sender[50];
    char sender_pwd[128];
    char receiver[50];
    char receiver_pubkey_input[16];
    double amount;
    printf("Enter sender username: ");
    scanf("%49s", sender);
    printf("Enter sender password: ");
    scanf("%127s", sender_pwd);
    printf("Enter receiver username: ");
    scanf("%49s", receiver);
    printf("Enter receiver public key (6 digits): ");
    scanf("%15s", receiver_pubkey_input);
    printf("Enter amount to send: ");
    scanf("%lf", &amount);
    int sidx = find_user_index(users, ucount, sender);
    if (sidx == -1) { 
        printf("Sender not found.\n"); 
        return; 
    }
    int ridx = find_user_index(users, ucount, receiver);
    if (ridx == -1) { 
        printf("Receiver not found.\n"); 
        return; 
    }
    char sender_hash_hex[65];
    sha256_hash_str(sender_pwd, sender_hash_hex);
    if (strcmp(sender_hash_hex, users[sidx].password) != 0) { 
        printf("Sender authentication failed.\n"); 
        return; 
    }
    if (amount <= 0.0) { 
        printf("Invalid amount.\n"); 
        return; 
    }
    if (users[sidx].balance < amount) { 
        printf("Insufficient balance.\n"); 
        return; 
    }
    char entered_pk_hash[65];
    sha256_hash_str(receiver_pubkey_input, entered_pk_hash);
    if (strcmp(entered_pk_hash, users[ridx].public_key_hash) != 0) { 
        printf("Receiver public key does not match stored public key hash. Aborting.\n"); 
        return; 
    }
    char mined_nonce[129];
    char mined_hash[65];
    int difficulty = 2;
    int ok = mine_signature_prefix(users[ridx].public_key_hash, difficulty, mined_nonce, mined_hash);
    if (!ok) { 
        printf("Mining failed to find a signature quickly; aborting.\n"); 
        return; 
    }
    users[sidx].balance -= amount;
    users[ridx].balance += amount;
    char amount_str[64];
    snprintf(amount_str, sizeof(amount_str), "%.2lf", amount);
    char tx_input[2048];
    snprintf(tx_input, sizeof(tx_input), "%s|%s|%s|%s|%s", sender, receiver, amount_str, mined_nonce, users[ridx].public_key);
    char tx_hash_base[65];
    sha256_hash_str(tx_input, tx_hash_base);
    char final_tx_hash[130];
    snprintf(final_tx_hash, sizeof(final_tx_hash), "%s%s", mined_hash, tx_hash_base);
    append_transaction_record(sender, receiver, amount, mined_nonce, final_tx_hash, users[ridx].public_key, "Transfer");
    if (!save_users(users, ucount, dbfile)) { 
        printf("Failed to save user database.\n"); 
        return; 
    }
    printf("\nTransaction created.\n");
    printf("Mining Logs:\n");
    printf("=====================================\n");
    printf("Mined nonce (used for signature): %s\n", mined_nonce);
    printf("Mined signature hash (prefixed): %s\n", mined_hash);
    printf("Final transaction hash (mined_sig + tx_hash): %s\n", final_tx_hash);
    printf("Receiver public key used in tx: %s\n", users[ridx].public_key);
    printf("=====================================\n");
}

void request_money(const char *dbfile) {
    UserData users[MAX_USERS];
    int ucount = load_users(users, MAX_USERS, dbfile);
    if (ucount <= 0) return;

    char requester_pk[50], payee_pk[50];
    double amount;

    printf("Enter your public key (requester): ");
    scanf("%49s", requester_pk);

    printf("Enter payee public key: ");
    scanf("%49s", payee_pk);

    int requester = -1, payee = -1;

    for (int i = 0; i < ucount; i++)
        if (strcmp(users[i].public_key, requester_pk) == 0)
            requester = i;

    for (int i = 0; i < ucount; i++)
        if (strcmp(users[i].public_key, payee_pk) == 0)
            payee = i;

    if (requester == -1) {
        printf("Requester public key not found.\n");
        return;
    }

    if (payee == -1) {
        printf("Payee public key not found.\n");
        return;
    }

    if (strcmp(users[requester].public_key_hash, users[payee].public_key_hash) == 0) {
        printf("payee and requester public key cannot be the same.\n");
        return;
    }

    printf("Enter amount to request: ");
    scanf("%lf", &amount);

    FILE *f = fopen("requests.csv", "a");
    if (!f) {
        f = fopen("requests.csv", "w");
        fprintf(f, "requester,receiver,amount,requester_public_key,timestamp\n");
    }

    fprintf(f, "%s,%s,%.2lf,%s,%ld\n",
        users[requester].username,
        users[payee].username,
        amount,
        users[requester].public_key,
        (long)time(NULL));

    fclose(f);

    printf("Money request sent successfully.\n");
}

void request_draft_menu(const char *dbfile, const char *current_user) {

    FILE *f = fopen("requests.csv", "r");
    if (!f) { 
        printf("No requests found.\n"); 
        return; 
    }

    char line[512];

    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        printf("No requests found.\n");
        return;
    }

    // Temporary arrays for all requests for this user
    char requester[100][50];
    char pubkey[100][16];
    double amount[100];
    long timestamp[100];
    int count = 0;

    while (fgets(line, sizeof(line), f)) {

        if (strlen(line) < 5) continue;

        char r1[50], r2[50], pk[20], amt_str[32], ts_str[32];
        r1[0]=r2[0]=pk[0]=amt_str[0]=ts_str[0]='\0';

        int fields = sscanf(line, "%49[^,],%49[^,],%31[^,],%15[^,],%31[^,\n]",
                            r1, r2, amt_str, pk, ts_str);

        if (fields < 5) continue;

        if (strcmp(r2, current_user) != 0) continue;

        strcpy(requester[count], r1);
        strcpy(pubkey[count], pk);
        amount[count] = atof(amt_str);
        timestamp[count] = atol(ts_str);

        count++;
    }

    fclose(f);

    if (count == 0) {
        printf("No pending requests for you.\n");
        return;
    }

    printf("\nPending Money Requests:\n");
    for (int i = 0; i < count; i++)
        printf("%d. %s requests Rs %.2lf\n", i+1, requester[i], amount[i]);

    printf("Enter request number (0 to cancel): ");
    int pick;
    scanf("%d", &pick);

    if (pick <= 0 || pick > count) return;
    pick--;

    printf("1. Accept Request\n2. Decline Request\nEnter choice: ");
    int choice;
    scanf("%d", &choice);

    UserData users[MAX_USERS];
    int ucount = load_users(users, MAX_USERS, dbfile);
    int uidx = find_user_index(users, ucount, current_user);
    if (uidx == -1) return;

    if (choice == 2) {
        printf("Request declined.\n");
    }

    else if (choice == 1) {

        char uname[50], pwd[128], hash[65];

        printf("Enter your username to confirm: ");
        scanf("%49s", uname);

        if (strcmp(uname, current_user) != 0) {
            printf("Username doesn't match.\n");
            return;
        }

        printf("Enter your password: ");
        scanf("%127s", pwd);

        sha256_hash_str(pwd, hash);

        if (strcmp(hash, users[uidx].password) != 0) {
            printf("Authentication failed.\n");
            return;
        }

        if (users[uidx].balance < amount[pick]) {
            printf("Insufficient balance.\n");
            return;
        }
        update_balance_and_record(dbfile, current_user, amount[pick], "Withdraw");
        update_balance_and_record(dbfile, requester[pick], amount[pick], "Deposit");

        printf("Money sent successfully!\n");
    }
    FILE *in = fopen("requests.csv", "r");
    FILE *out = fopen("requests.tmp", "w");

    char buf[512];

    fgets(buf, sizeof(buf), in);
    fprintf(out, "%s", buf);

    while (fgets(buf, sizeof(buf), in)) {

        char r1[50], r2[50], pk[20], amt_str[32], ts_str[32];

        int fields = sscanf(buf, "%49[^,],%49[^,],%31[^,],%15[^,],%31[^,\n]",
                            r1, r2, amt_str, pk, ts_str);

        if (fields < 5) continue;

        if (strcmp(r1, requester[pick]) == 0 &&
            strcmp(r2, current_user) == 0 &&
            strcmp(pk, pubkey[pick]) == 0)
            continue;

        fprintf(out, "%s", buf);
    }

    fclose(in);
    fclose(out);
    remove("requests.csv");
    rename("requests.tmp", "requests.csv");
}


// Dwij's part of code(modified)
void new_user(const char *dbfile) {
   UserData user;
    UserData users[MAX_USERS];
    int ucount = load_users(users, MAX_USERS, dbfile);
    if (ucount < 0) ucount = 0;
    while (1) {
        printf("Enter Username: ");
        scanf("%49s", user.username);
        int idx = find_user_index(users, ucount, user.username);
        if (idx != -1) {
            printf("Username already exists ! Please choose another.\n");
        } else {
            break; 
        }
    }
    printf("Enter Password: ");
    scanf("%127s", user.password);
    printf("Enter Balance: ");
    scanf("%lf", &user.balance);
    printf("Enter Loan: ");
    scanf("%lf", &user.loan);
    user.credit = 0.0;
    user.debit  = 0.0;
    char passhash[65];
    sha256_hash_str(user.password, passhash);
    strncpy(user.password, passhash, sizeof(user.password) - 1);
    user.password[sizeof(user.password) - 1] = '\0';
    char new_pk[16];
    generate_unique_public_key(users, ucount, new_pk, 6);
    char pk_hash[65];
    sha256_hash_str(new_pk, pk_hash);
    strncpy(user.public_key, new_pk, sizeof(user.public_key) - 1);
    user.public_key[sizeof(user.public_key) - 1] = '\0';
    strncpy(user.public_key_hash, pk_hash, sizeof(user.public_key_hash) - 1);
    user.public_key_hash[sizeof(user.public_key_hash) - 1] = '\0';
    FILE *file = fopen(dbfile, "a+");
    if (!file) { 
        printf("Error opening file.\n"); 
        return; 
    }
    fseek(file, 0, SEEK_END);
    long fsize = ftell(file);
    if (fsize == 0)
        fprintf(file, "username,password_hash,public_key,public_key_hash,balance,loan,credit,debit\n");
    fprintf(file, "\n%s,%s,%s,%s,%.2lf,%.2lf,%.2lf,%.2lf,",
            user.username, user.password, user.public_key, user.public_key_hash,
            user.balance, user.loan, user.credit, user.debit);
    fclose(file);
    printf("User added successfully.\n");
    printf("Assigned public key (show only now): %s\n", user.public_key);
}

void displayUser(const char *dbfile, const char *username, const char *password, int *flag) {
    UserData users[MAX_USERS];
    int cnt = load_users(users, MAX_USERS, dbfile);
    if (cnt <= 0) { 
        printf("No users found.\n");
        *flag = 0; 
        return; 
    }
    int idx = find_user_index(users, cnt, username);
    if (idx == -1) { 
        printf("User not found.\n");
        *flag = 0; 
        return; 
    }
    char passhash[65];
    sha256_hash_str(password, passhash);
    if (strcmp(passhash, users[idx].password) != 0) { 
        printf("Incorrect password.\n");
        *flag = 0; 
        return; 
    }
    printf("Welcome %s. Balance: Rs. %.2lf\n", users[idx].username, users[idx].balance);
    printf("Public key: %s\n", users[idx].public_key);
}
// Adhyayan's part of code(modified)
void Menu() {
    printf("\n==== Bank Menu ====\n");
    printf("1. Deposit Money\n");
    printf("2. Withdraw Money\n");
    printf("3. View user details\n");
    printf("4. Send Money\n");
    printf("5. Add/Regenerate Public Key\n");
    printf("6. Request Money\n");
    printf("7. Request Draft\n");
    printf("8. Exit\n");
}

void update_balance_and_record(const char *dbfile, const char *username, double amount, const char *type) {
    UserData users[MAX_USERS];
    int count = load_users(users, MAX_USERS, dbfile);
    if (count <= 0) {
        printf("Error loading users.\n");
        return;
    }

    int idx = find_user_index(users, count, username);
    if (idx == -1) {
        printf("User not found.\n");
        return;
    }

    if (strcmp(type, "Deposit") == 0) {
        users[idx].balance += amount;
        printf("Rs %.2lf deposited successfully!\n", amount);
    }
    else if (strcmp(type, "Withdraw") == 0) {
        if (amount > users[idx].balance) {
            printf("Insufficient balance!\n");
            return;
        }
        users[idx].balance -= amount;
        printf("Rs %.2lf withdrawn successfully!\n", amount);
    }
    

    append_transaction_record(username, "-", amount, "N/A", "N/A", "N/A", type);
}
