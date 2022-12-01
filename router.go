package main

// func insertLockedCRL(w http.ResponseWriter, r *http.Request) {
// 	if err := UpdateCRLOfChannelConfig(ADD_LOCKED_CRL, fmt.Sprintf(userCertTemplate, USER1), "mychannel"); err != nil {
// 		io.WriteString(w, err.Error())
// 		return
// 	}
// 	io.WriteString(w, "ok")
// }

// func insertBadCRL(w http.ResponseWriter, r *http.Request) {
// 	if err := UpdateCRLOfChannelConfig(ADD_INVALID_CRL, fmt.Sprintf(userCertTemplate, USER1), "mychannel"); err != nil {
// 		io.WriteString(w, err.Error())
// 		return
// 	}
// 	io.WriteString(w, "ok")
// }

// func cleanCRL(w http.ResponseWriter, r *http.Request) {
// 	if err := UpdateCRLOfChannelConfig(CLEAN_CRL, fmt.Sprintf(userCertTemplate, USER1), "mychannel"); err != nil {
// 		io.WriteString(w, err.Error())
// 		return
// 	}
// 	io.WriteString(w, "ok")
// }

// func genValidCRL(w http.ResponseWriter, r *http.Request) {
// 	crl, err := GenCRL()
// 	if err != nil {
// 		io.WriteString(w, err.Error())
// 		return
// 	}
// 	log.Printf("\n%s\n", crl)
// 	io.WriteString(w, "ok")
// }

// func operateFabricResource(w http.ResponseWriter, r *http.Request) {
// 	if err := opFab(); err != nil {
// 		io.WriteString(w, err.Error())
// 		return
// 	}
// 	io.WriteString(w, "ok")
// }
