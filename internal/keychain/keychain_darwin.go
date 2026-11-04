// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

//go:build darwin && cgo

package keychain

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// mk_status_locked reports whether kc (or the default keychain when kc is
// NULL) is known to be locked. It returns 0 when the state cannot be read.
static int mk_status_locked(SecKeychainRef kc) {
	SecKeychainRef target = kc;
	SecKeychainRef def = NULL;
	if (target == NULL) {
		if (SecKeychainCopyDefault(&def) != errSecSuccess || def == NULL) {
			return 0;
		}
		target = def;
	}
	SecKeychainStatus st = 0;
	OSStatus rc = SecKeychainGetStatus(target, &st);
	if (def != NULL) {
		CFRelease(def);
	}
	if (rc != errSecSuccess) {
		return 0;
	}
	return (st & kSecUnlockStateStatus) == 0;
}

// mk_find_password runs one SecItemCopyMatching for a password item and
// returns its data in *out (to be released by the caller). The keychain
// search is limited to keychain_path when it is not NULL. On failure,
// *locked reports whether the searched keychain is locked.
static OSStatus mk_find_password(int internet,
                                 const char *primary, long primary_len,
                                 const char *account, long account_len,
                                 const char *keychain_path,
                                 CFDataRef *out, int *locked) {
	OSStatus status = errSecSuccess;
	SecKeychainRef kc = NULL;
	CFStringRef primary_ref = NULL;
	CFStringRef account_ref = NULL;
	CFArrayRef search_list = NULL;
	CFMutableDictionaryRef query = NULL;
	CFTypeRef result = NULL;

	*out = NULL;
	*locked = 0;

	if (keychain_path != NULL) {
		status = SecKeychainOpen(keychain_path, &kc);
		if (status != errSecSuccess) {
			goto done;
		}
	}

	primary_ref = CFStringCreateWithBytes(NULL, (const UInt8 *)primary, primary_len, kCFStringEncodingUTF8, false);
	account_ref = CFStringCreateWithBytes(NULL, (const UInt8 *)account, account_len, kCFStringEncodingUTF8, false);
	query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (primary_ref == NULL || account_ref == NULL || query == NULL) {
		status = errSecParam;
		goto done;
	}

	CFDictionarySetValue(query, kSecClass, internet ? kSecClassInternetPassword : kSecClassGenericPassword);
	CFDictionarySetValue(query, internet ? kSecAttrServer : kSecAttrService, primary_ref);
	CFDictionarySetValue(query, kSecAttrAccount, account_ref);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	if (kc != NULL) {
		const void *keychains[] = { kc };
		search_list = CFArrayCreate(NULL, keychains, 1, &kCFTypeArrayCallBacks);
		if (search_list == NULL) {
			status = errSecAllocate;
			goto done;
		}
		CFDictionarySetValue(query, kSecMatchSearchList, search_list);
	}

	status = SecItemCopyMatching(query, &result);
	if (status != errSecSuccess) {
		if (status != errSecItemNotFound) {
			*locked = mk_status_locked(kc);
		}
		goto done;
	}
	if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
		status = errSecDecode;
		goto done;
	}
	*out = (CFDataRef)result;
	result = NULL;

done:
	if (result != NULL) CFRelease(result);
	if (query != NULL) CFRelease(query);
	if (search_list != NULL) CFRelease(search_list);
	if (account_ref != NULL) CFRelease(account_ref);
	if (primary_ref != NULL) CFRelease(primary_ref);
	if (kc != NULL) CFRelease(kc);
	return status;
}

// mk_error_message returns the Security framework's description of status as
// a malloc'd UTF-8 C string, or NULL. The caller frees it.
static char *mk_error_message(OSStatus status) {
	CFStringRef msg = SecCopyErrorMessageString(status, NULL);
	if (msg == NULL) {
		return NULL;
	}
	CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(msg), kCFStringEncodingUTF8) + 1;
	char *buf = malloc((size_t)max);
	if (buf != NULL && !CFStringGetCString(msg, buf, max, kCFStringEncodingUTF8)) {
		free(buf);
		buf = NULL;
	}
	CFRelease(msg);
	return buf;
}

static void mk_set_interaction_allowed(int allowed) {
	SecKeychainSetUserInteractionAllowed(allowed ? true : false);
}
*/
import "C"

import (
	"os"
	"unicode/utf8"
	"unsafe"
)

// FindPassword returns the data of the first password item that matches q.
// It returns an *Error for keychain failures and a plain error for an
// invalid query.
func FindPassword(q Query) (string, error) {
	if err := q.Validate(); err != nil {
		return "", err
	}

	var cPath *C.char
	if q.Keychain != "" {
		// SecKeychainOpen succeeds for a missing file and the later search
		// reports "item not found", so check the file first to say what is
		// actually wrong.
		info, err := os.Stat(q.Keychain)
		switch {
		case os.IsNotExist(err):
			return "", &Error{Code: CodeKeychainNotFound}
		case err != nil:
			return "", &Error{Code: CodeOther, Message: err.Error()}
		case info.IsDir():
			return "", &Error{Code: CodeKeychainNotFound, Message: "the path is a directory"}
		}
		cPath = C.CString(q.Keychain)
		defer C.free(unsafe.Pointer(cPath))
	}

	internet := C.int(0)
	if q.Kind == InternetPassword {
		internet = 1
	}

	primary := []byte(q.Service)
	account := []byte(q.Account)

	var data C.CFDataRef
	var locked C.int
	status := C.mk_find_password(
		internet,
		(*C.char)(unsafe.Pointer(&primary[0])), C.long(len(primary)),
		(*C.char)(unsafe.Pointer(&account[0])), C.long(len(account)),
		cPath,
		&data, &locked,
	)
	if status != C.errSecSuccess {
		return "", statusError(int32(status), locked != 0)
	}
	defer C.CFRelease(C.CFTypeRef(data))

	length := C.CFDataGetLength(data)
	if length == 0 {
		return "", nil
	}
	buf := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), C.int(length))
	defer clear(buf)

	if !utf8.Valid(buf) {
		return "", &Error{Code: CodeInvalidData}
	}
	return string(buf), nil
}

// SetUserInteractionAllowed sets, for the whole process, whether the
// Security framework may show dialogs (unlock prompts and access
// confirmations). It is allowed by default. Tests disable it so that a
// misconfigured test fails instead of waiting on a dialog.
func SetUserInteractionAllowed(allowed bool) {
	v := C.int(0)
	if allowed {
		v = 1
	}
	C.mk_set_interaction_allowed(v)
}

func statusError(status int32, locked bool) *Error {
	e := &Error{Code: classify(status, locked), Status: status}
	if msg := C.mk_error_message(C.OSStatus(status)); msg != nil {
		e.Message = C.GoString(msg)
		C.free(unsafe.Pointer(msg))
	}
	return e
}
