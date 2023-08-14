package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"bytes"
	"strconv"
	"time"
)

// Global variables to be imported before script runtime
var (
	WHITELISTED_IP    = os.Getenv("WHITELISTED_IP")
	AUTHORIZATION_KEY = os.Getenv("AUTHORIZATION_KEY")

	TRACKIT_API_URL = os.Getenv("TRACKIT_API_URL")
	TRACKIT_USERNAME = os.Getenv("TRACKIT_USERNAME")
	TRACKIT_PASSWORD = os.Getenv("TRACKIT_PASSWORD")
)

// Struct used to format the body for a CREATE/POST
// endpoint in TrackIT's API
type MutateWorkOrder struct {
	RequestorName string `json:"RequestorName"`
	CallbackNumber string `json:"RequestorPhoneNumber"`
	Summary string `json:"Summary"`
	Priority int `json:"Priority"`
	Type string `json:"Type"`
	Subtype string `json:"SubType"`
	Category string `json:"Category"`
}

//
// Struct to unmarshal the JSON response from the
// TrackIT API work order request / response
//
type WorkOrderNote struct {
    CreatedBy         string `json:"CreatedBy"`
    CreatedDate       string `json:"CreatedDate"`
    IsPrivate         string `json:"IsPrivate"`
    FullText          string `json:"FullText"`
    WorkOrderNoteType string `json:"WorkOrderNoteTypeId"`
    IsTextMessage     string `json:"IsTextMessage"`
    RecipientType     string `json:"RecipientType"`
    WorkEfforts       string `json:"WorkEfforts"`
    ActivityCode      string `json:"ActivityCode"`
    IsNoteTruncated   string `json:"IsNoteTruncated"`
    MessageType       string `json:"MessageType"`
}

//
// Struct to hold the WorkOrder
// data returned from the API
//
type WorkOrder struct {
    AssetName               string            `json:"AssetName"`
    AssignedTechnician      string            `json:"AssignedTechnician"`
    TechnicianEmailAddress  string            `json:"TechnicianEmailAddress"`
    TechnicianSmsEmailAddress string          `json:"TechnicianSmsEmailAddress"`
    Category                string            `json:"Category"`
    ResponseDate            string            `json:"ResponseDate"`
    RespondedDate           string            `json:"RespondedDate"`
    RespondedBy             string            `json:"RespondedBy"`
    AssignedDate            string            `json:"AssignedDate"`
    RequestorEnteredDate    string            `json:"RequestorEnteredDate"`
    EnteredCompletionDate   string            `json:"EnteredCompletionDate"`
    ExpectedCompletionDate  string            `json:"ExpectedCompletionDate"`
    HasSkillRoutingExecuted string            `json:"HasSkillRoutingExecuted"`
    ID                      string            `json:"Id"`
    Location                string            `json:"Location"`
    Department              string            `json:"Department"`
    Hours                   string            `json:"Hours"`
    Charge                  string            `json:"Charge"`
    IsClosed                string            `json:"IsClosed"`
    Priority                string            `json:"Priority"`
    RequestorName           string            `json:"RequestorName"`
    RequestorPhoneNumber    string            `json:"RequestorPhoneNumber"`
    NotificationCcAddress   string            `json:"NotificationCcAddress"`
    NotificationBccAddress  string            `json:"NotificationBccAddress"`
    StatusName              string            `json:"StatusName"`
    SubType                 string            `json:"SubType"`
    Summary                 string            `json:"Summary"`
    Type                    string            `json:"Type"`
    UdfText1                string            `json:"UdfText1"`
    UdfText2                string            `json:"UdfText2"`
    UdfText3                string            `json:"UdfText3"`
    UdfText4                string            `json:"UdfText4"`
    UdfText5                string            `json:"UdfText5"`
    UdfText6                string            `json:"UdfText6"`
    UdfDate1                string            `json:"UdfDate1"`
    UdfDate2                string            `json:"UdfDate2"`
    UdfDate3                string            `json:"UdfDate3"`
    UdfDate4                string            `json:"UdfDate4"`
    UdfNumeric              string            `json:"UdfNumeric"`
    UdfInt                  string            `json:"UdfInt"`
    UdfLookup1              string            `json:"UdfLookup1"`
    UdfLookup2              string            `json:"UdfLookup2"`
    UdfLookup3              string            `json:"UdfLookup3"`
    UdfLookup4              string            `json:"UdfLookup4"`
    UdfLookup5              string            `json:"UdfLookup5"`
    UdfLookup6              string            `json:"UdfLookup6"`
    UdfLookup7              string            `json:"UdfLookup7"`
    UdfLookup8              string            `json:"UdfLookup8"`
    AttachmentCount         string            `json:"AttachmentCount"`
    AssignmentCount         string            `json:"AssignmentCount"`
    IsAssignment            string            `json:"IsAssignment"`
    IsIncident              string            `json:"IsIncident"`
    IsIncidentTemplate      string            `json:"IsIncidentTemplate"`
    IsAssignmentTemplate    string            `json:"IsAssignmentTemplate"`
    ParentIncidentID        string            `json:"ParentIncidentId"`
    WasLocked               string            `json:"WasLocked"`
    IsReadOnly              string            `json:"IsReadOnly"`
    IsClockStopped          string            `json:"IsClockStopped"`
    Notes                   map[string]WorkOrderNote   `json:"Notes"`
}

//
// Struct to hold the WorkOrder information returned
// from a TrackIT API response body
//
type WorkOrderResponse struct {
    Success string `json:"success"`
    WorkOrder    WorkOrder   `json:"data"`
}

// 
// Struct to unmarshal the JSON response from the
// TrackIT API access token request
//
type TokenResponse struct {
	Success string `json:"success"`
	Data    struct {
		APIKey string `json:"apiKey"`
	} `json:"data"`
}

// Helper function to handle authentication
// Pass it the request, it'll utilize helper functions
// to determine if the IP is whitelisted, and if the
// authorization token is valid.
func authenticate(request *http.Request) bool {
	// Get the IP address of the request
	ip := getRequestIP(request)
	token := getTokenFromRequest(request)

	// Check if the IP is whitelisted
	if WHITELISTED_IP != ip {
		log.Printf("IP address %s is not whitelisted", ip)
		return false
	}

	// Check if the token is valid
	if AUTHORIZATION_KEY != token {
		log.Printf("Authorization token %s is not valid", token)
		return false
	}

	// If we made it this far, the request is authenticated
	return true
}

// Helper function to take a given request, and return
// the IP that the request is coming from.
//
// If no IP is found, an empty string is returned ("")
func getRequestIP(request *http.Request) string {
	// Get the IP address from the RemoteAddr field
	ip, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		// Handle error if unable to parse the IP address
		return ""
	}

	// Return the IP address
	return ip
}

// Helper function to take a given request, and return
// the authorization Bearer token. Header must be in form:
// "Authorization" : "Bearer TOKEN_GOES_HERE"
//
// If no token or authorization header is found, the returned string
// will be empty ("")
func getTokenFromRequest(request *http.Request) string {
	// Get the Authorization header value
	authHeader := request.Header.Get("Authorization")

	// Check if the Authorization header is present
	if authHeader == "" {
		log.Printf("Authorization header is missing")
		return ""
	}

	// Extract the token from the header value
	// Assuming the token is present as a bearer token
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Check if token has been changed (basically proving logic that
	// the token was present as a bearer token)
	if token == authHeader {
		log.Printf("Authorization header is not a bearer token")
		return ""
	}

	// Now we now auth header is present, in bearer form, so
	// we return the token
	return token
}


func getQueryParameter(request *http.Request, parameter string) string {
	// Get the query parameter from the request
	queryParameter := request.URL.Query().Get(parameter)

	return queryParameter
}

// Utility function to handle the API request to Track-IT! needed to generate
// an access token for future requests
func getAccessToken() string {
	url := fmt.Sprintf("http://%s/TrackitWebAPI/api/login?username=%s&pwd=%s", TRACKIT_API_URL, TRACKIT_USERNAME, TRACKIT_PASSWORD)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Failed to create access token request:", err)
		return ""
	}
	
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Access token request failed:", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Request returned non-OK status:", resp.Status)
		return ""
	}

	var tokenResponse TokenResponse

	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)

	if err != nil {
		fmt.Println("Failed to parse response JSON:", err)
		return ""
	}

	if tokenResponse.Success != "true" {
		fmt.Println("Request was not successful")
		return ""
	}

	return tokenResponse.Data.APIKey
}

// Utility function to handle the API request to Track-IT! and return
// the resultant Struct
func getWorkOrder(id int) WorkOrder {
	var workOrderResponse WorkOrderResponse

	url := fmt.Sprintf("http://%s/TrackitWebAPI/api/workorder/Get/%s", TRACKIT_API_URL, strconv.Itoa(id))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Failed to create work order get request: ", err)
		return workOrderResponse.WorkOrder
	}

	accessToken := getAccessToken()

	fmt.Println("Retrieved Access Token: " + accessToken)

	req.Header.Set("TrackItAPIKey", getAccessToken())

	client := http.DefaultClient
	resp, err := client.Do(req)

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Request returned non-OK status: ", resp.Status)
		return workOrderResponse.WorkOrder
	}

	err = json.NewDecoder(resp.Body).Decode(&workOrderResponse)

	if err != nil {
		fmt.Println("Failed to parse response JSON: ", err)
		return workOrderResponse.WorkOrder
	}

	if workOrderResponse.Success == "false" {
		fmt.Println("Retrieval request was unsuccessful")
		return workOrderResponse.WorkOrder
	}

	return workOrderResponse.WorkOrder
}

// Utility function to handle the API request to Track-IT! to create
// a new work order
func createWorkOrder(requestor string, callback string, summary string, priority int, orderType string, orderSubtype string) (WorkOrder) {
	var workOrderResponse WorkOrderResponse

	url := fmt.Sprintf("http://%s/TrackitWebAPI/api/workorder/Create", TRACKIT_API_URL)

	mutateData := MutateWorkOrder {
		RequestorName: requestor,
		CallbackNumber: callback,
		Summary: summary,
		Priority: priority,
		Type: orderType,
		Subtype: orderSubtype,
		Category: "Request",
	}

	jsonMutateData, err := json.Marshal(mutateData)
	if err != nil {
		fmt.Println("Failed to marshal parameters into a proper JSON request body. ", err)
		return workOrderResponse.WorkOrder
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonMutateData))
	if err != nil {
		fmt.Println("Failed to create work order post request: ", err)
		return workOrderResponse.WorkOrder
	}

	req.Header.Set("TrackItAPIKey", getAccessToken())

	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request to create work order failed with error: ", err)
		return workOrderResponse.WorkOrder
	}

	err = json.NewDecoder(resp.Body).Decode(&workOrderResponse)
	if err != nil {
		fmt.Println("Reading the JSON response from Track-IT failed with error: ", err)
		return workOrderResponse.WorkOrder
	}

	if workOrderResponse.Success == "false" {
		fmt.Println("Creation request was unsuccessful")
		return workOrderResponse.WorkOrder
	}

	return workOrderResponse.WorkOrder
}

// Recieve a given request and format a response based
// on whether or not the request is authenticated.
// If the request is authenticated, return a 200 OK
// If the request is not authenticated, return a 401 Unauthorized
func authTester(w http.ResponseWriter, r *http.Request) {
	// Check if the request is authenticated
	if authenticate(r) {
		// If the request is authenticated, return a 200 OK
		w.WriteHeader(http.StatusOK)
	} else {
		// If the request is not authenticated, return a 401 Unauthorized
		w.WriteHeader(http.StatusUnauthorized)
	}
}

// Retrieve a work order by a given ID
func returnWorkOrder(w http.ResponseWriter, r *http.Request) {
	if authenticate(r) {
		// Request is authenticated
		// Attempt to write struct to ResponseWriter
		id, err := strconv.Atoi(getQueryParameter(r, "id"))

		if(err != nil) {
			http.Error(w, "The passed ID is not an integer!", http.StatusInternalServerError)
			return
		}

		//Properly formatted request
		w.Header().Set("Content-Type", "application/json")

		jsonResponse, err := json.Marshal(getWorkOrder(id))
		if err != nil {
			//Raise generic error
			http.Error(w, "The passed ID failed when attempting to retrieve the associated work order.", http.StatusInternalServerError)
		}

		_, err = w.Write(jsonResponse)
		if err != nil {
			http.Error(w, "Error writing the WorkOrder response payload!", http.StatusInternalServerError)
		}

		return
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}



func main() {
	listenAddr := ":8080"
	if val, ok := os.LookupEnv("FUNCTIONS_CUSTOMHANDLER_PORT"); ok {
		log.Printf("Found custom functions port (%s), using that value instead of default (8080)...", val)
		listenAddr = ":" + val
	}

	server := &http.Server {
		Addr: listenAddr,
		ReadHeaderTimeout: 5 * time.Second,
	}

	http.HandleFunc("/api/bouncer", authTester)
	http.HandleFunc("/api/getWorkOrder", returnWorkOrder)
	
	log.Printf("About to listen on %s. Go to https://localhost%s/", listenAddr, listenAddr)
	log.Fatal(server.ListenAndServe())
}