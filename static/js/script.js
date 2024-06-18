// Function to handle login
/*function login(username, password) {
    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username: username, password: password })
    })
    .then(response => response.json())
    .then(data => {
        if (data.access_token) {
            localStorage.setItem('jwt_token', data.access_token);
            alert('Login successful');
        } else {
            alert('Login failed');
        }
    })
    .catch(error => console.error('Error:', error));
}

// Function to handle image upload
function uploadImage(file) {
    const token = localStorage.getItem('jwt_token');

    const formData = new FormData();
    formData.append('file', file);

    fetch('/upload', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`
        },
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            window.location.href = `/result?filename=${data.filename}`;
        } else {
            alert(data.error);
        }
    })
    .catch(error => console.error('Error:', error));
}

fetch('/login', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ username: 'admin', password: 'password' })
})
.then(response => response.json())
.then(data => {
    localStorage.setItem('access_token', data.access_token);
})
.catch(error => console.error('Error:', error));
*/
fetch('/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      username: 'root',
      password: 'root'
    })
  })
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error('Error:', error));
  