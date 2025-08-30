package main

import (
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
)

func main() {
	err := initGlobals()
	if err != nil {
		fmt.Println(err)
		return
	}

	router := mux.NewRouter()

	router.PathPrefix("/oauth2/css/").Handler(http.StripPrefix("/oauth2/css/",
		http.FileServer(http.Dir(filepath.Join(Basepath, "template/css/")))))
	router.PathPrefix("/oauth2/js/").Handler(http.StripPrefix("/oauth2/js/",
		http.FileServer(http.Dir(filepath.Join(Basepath, "template/js/")))))

	router.Methods("POST").Path("/oauth2/signup").Handler(
		negroni.New(
			negroni.HandlerFunc(handleSignUp),
		))
	router.Methods("POST").Path("/oauth2/signin").Handler(
		negroni.New(
			negroni.HandlerFunc(handleSignIn),
		))
	router.Methods("POST").Path("/oauth2/token").Handler(
		negroni.New(
			negroni.HandlerFunc(handleToken),
		))
	router.Methods("GET").Path("/oauth2/authorize").Handler(
		negroni.New(
			negroni.HandlerFunc(handleAuthorize),
		))
	router.Methods("GET").Path("/oauth2/userinfo").Handler(
		negroni.New(
			negroni.HandlerFunc(handleUserInfo),
		))
	router.Methods("POST").Path("/oauth2/revoke").Handler(
		negroni.New(
			negroni.HandlerFunc(handleRevoke),
		))
	router.Methods("POST").Path("/oauth2/introspect").Handler(
		negroni.New(
			negroni.HandlerFunc(handleIntrospect),
		))
	router.Methods("GET").Path("/oauth2/.well-known/jwks.json").Handler(
		negroni.New(
			negroni.HandlerFunc(handleJwks),
		))
	router.Methods("GET", "POST").Path("/oauth2/logout").Handler(
		negroni.New(
			negroni.HandlerFunc(handleLogout),
		))
	router.Methods("POST").Path("/oauth2/account/update").Handler(
		negroni.New(
			negroni.HandlerFunc(handleAccountUpdate),
		))
	router.Methods("GET").Path("/oauth2/account/all").Handler(
		negroni.New(
			negroni.HandlerFunc(handleAccountAll),
		))

	router.Methods("GET").Path("/oauth2/register").Handler(
		negroni.New(
			negroni.HandlerFunc(handleRegister),
		))
	router.Methods("GET").Path("/oauth2/login").Handler(
		negroni.New(
			negroni.HandlerFunc(handleLogin),
		))
	router.Methods("GET").Path("/oauth2/dashboard").Handler(
		negroni.New(
			negroni.HandlerFunc(handleDashboard),
		))

	server := negroni.New(negroni.NewRecovery())
	//server.Use(bha.NewCORSHandler(nil, nil, nil))
	server.Use(negroni.NewLogger())
	server.UseHandler(router)

	for _, v := range mainConfig.ListenList {
		if !v.Enable {
			continue
		}
		v1 := v
		switch v1.LowercaseProtocol() {
		case "http":
			go func() {
				err = http.ListenAndServe(fmt.Sprintf(":%v", v1.Port),
					server)
				if err != nil {
					fmt.Println(err)
				}
			}()
		case "https":
			go func() {
				s := &http.Server{
					Addr:    fmt.Sprintf(":%v", v1.Port),
					Handler: server,
				}
				s.SetKeepAlivesEnabled(false)
				err = s.ListenAndServeTLS(mainConfig.HttpsCrtFile, mainConfig.HttpsKeyFile)
				if err != nil {
					fmt.Println(err)
				}
			}()
		}
	}
	select {}
}
