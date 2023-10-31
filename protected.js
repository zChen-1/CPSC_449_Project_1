fetch('/protected', {
    method: 'GET',
    headers: {
        'Authorization': 'Bearer ' + jwtToken,
    },
})
.then(response => response.json())
.then(data => {
    console.log(data);
})
.catch(error => {
    console.error('Error:', error);
});
