
document.querySelector('#signupForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.querySelector('#username').value;
  const password = document.querySelector('#password').value;

  const res = await fetch('/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });

  const data = await res.json();
  if (res.ok) {
    alert('Signup successful! Redirecting to login...');
    window.location.href = '/login';
  } else {
    alert(data.message || 'Signup failed');
  }
});
