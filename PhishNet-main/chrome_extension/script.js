// document.addEventListener('DOMContentLoaded', () => {
//     const urlSpan = document.getElementById('currentUrl');
//     const mainResultSpan = document.getElementById('analysisResult');
//     const mainResultCard = document.getElementById('mainResult');
//     const detailedResultsDiv = document.getElementById('detailedResults');
//     const errorMessageDiv = document.getElementById('errorMessage');

//     // Function to update the UI with feature results
//     const updateFeatureCard = (featureName, label) => {
//         const element = document.getElementById(featureName);
//         if (element && window.analysisData && window.analysisData.features) {
//             const value = window.analysisData.features[featureName];
//             element.textContent = `${label}: ${value === -1 ? 'Suspicious' : 'OK'}`;
//             element.classList.add(value === -1 ? 'suspicious' : 'safe');
//         }
//     };

//     // Function to display error messages
//     const displayError = (message) => {
//         errorMessageDiv.textContent = message;
//         errorMessageDiv.style.display = 'block';
//         mainResultCard.style.display = 'none';
//         detailedResultsDiv.style.display = 'none';
//     };

//     // Get the active tab to find its URL
//     chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
//         const currentTab = tabs[0];
//         if (!currentTab || !currentTab.url) {
//             displayError("Could not get current tab's URL.");
//             return;
//         }

//         const currentUrl = currentTab.url;
//         urlSpan.textContent = currentUrl;

//         // Make a single API call to the consolidated backend
//         fetch('http://localhost:5002/analyze_url', {
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/json',
//             },
//             body: JSON.stringify({ url: currentUrl }),
//         })
//         .then(response => {
//             if (!response.ok) {
//                 throw new Error(`Network response was not ok (Status: ${response.status})`);
//             }
//             return response.json();
//         })
//         .then(data => {
//             // Store data globally for helper functions
//             window.analysisData = data;

//             // Update main result
//             mainResultSpan.textContent = data.result;
//             mainResultCard.classList.add(data.result.includes("suspicious") ? 'suspicious' : 'safe');

//             // Update detailed feature cards
//             detailedResultsDiv.style.display = 'grid';
//             updateFeatureCard('Hppts', 'HTTPS');
//             updateFeatureCard('IframeRedirection', 'Iframe');
//             updateFeatureCard('UsingIp', 'IP URL');
//             updateFeatureCard('DisableRightClick', 'Right Click');
//             updateFeatureCard('shortUrl', 'Tiny URL');
//             updateFeatureCard('WebsiteForwarding', 'Forwarding');
//         })
//         .catch(error => {
//             console.error('Error:', error);
//             displayError('Failed to get analysis. Is the backend server running?');
//         });
//     });
// });

chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const currentTab = tabs[0];
    const currentUrl = currentTab.url;

    chrome.scripting.executeScript({
        target: { tabId: currentTab.id },
        function: (url) => {
            const currUrlElement = document.getElementById('currUrl');
            if (currUrlElement) {
                currUrlElement.textContent = url;
            }
        },
        args: [currentUrl],
    });

    console.log(currentUrl);

    // Now, you can use the currentUrl to make the fetch request
    const requestData = {
        url: currentUrl,
    };

    fetch('http://localhost:5002/analyze_url', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData),
    })
        .then((response) => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then((data) => {
            console.log('Analysis Response of the model:', data);
            // Handle the analysis response here
            chrome.scripting.executeScript({
                target: { tabId: currentTab.id },
                function: (analysisData) => {
                    // Send a message to the popup with the analysis data
                    chrome.runtime.sendMessage({
                        type: 'updateAnalysisData',
                        data: analysisData,
                    });
                },
                args: [data],
            });

            const result = data.result;
            const caution = data.caution;
            const predictionScore = data.prediction_score;
            const modelProbabilityScore = data.model_probability_score;
            const combinedScore = data.combined_score;

            // Check if the result is dangerous and block the webpage if it is
            if (model_probability_score <= 87) {
                chrome.tabs.update(currentTab.id, { url: 'google.com' });
            }
        })
        .catch((error) => {
            console.log(error)
        });

});


// chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
//     const currentTab = tabs[0];
//     const currentUrl = currentTab.url;

//     chrome.scripting.executeScript({
//         target: { tabId: currentTab.id },
//         function: (url) => {
//             const currUrlElement = document.getElementById('currUrl');
//             if (currUrlElement) {
//                 currUrlElement.textContent = url;
//             }
//         },
//         args: [currentUrl],
//     });

//     console.log(currentUrl);

//     // Now, you can use the currentUrl to make the fetch request
//     const requestData = {
//         url: currentUrl,
//     };

//     fetch('http://localhost:5000/analyze_url', {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/json',
//         },
//         body: JSON.stringify(requestData),
//     })
//         .then((response) => {
//             if (!response.ok) {
//                 throw new Error('Network response was not ok');
//             }
//             return response.json();
//         })
//         .then((data) => {
//             console.log('Analysis Response of the model:', data);
//             // Handle the analysis response here
//             chrome.scripting.executeScript({
//                 target: { tabId: currentTab.id },
//                 function: (analysisData) => {
//                     // Send a message to the popup with the analysis data
//                     chrome.runtime.sendMessage({
//                         type: 'updateAnalysisData',
//                         data: analysisData,
//                     });
//                 },
//                 args: [data],
//             });

//             // const result = data.result;
//             // const caution = data.caution;
//             // const predictionScore = data.prediction_score;
//             // const modelProbabilityScore = data.model_probability_score;
//             // const combinedScore = data.combined_score;

//         })
//         .catch((error) => {
//             console.log(error)
//         });

//         fetch('http://localhost:5000/tickNotTick', {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/json',
//         },
//         body: JSON.stringify(requestData),
//     })
//         .then((response) => {
//             if (!response.ok) {
//                 throw new Error('Network response was not ok');
//             }
//             return response.json();
//         })
//         .then((data) => {
//             console.log('Analysis Response of tick not tick:', data);
//             // Handle the analysis response here
//             // const result = data.result;
//             // const caution = data.caution;
//             // const predictionScore = data.prediction_score;
//             // const modelProbabilityScore = data.model_probability_score;
//             // const combinedScore = data.combined_score;

//         })
//         .catch((error) => {
//             console.log(error)
//         });
// });