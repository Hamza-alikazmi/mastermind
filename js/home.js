function handleLogin(role) {
    // Store the selected role in sessionStorage
    sessionStorage.setItem('selectedRole', role);
    window.location.href = `/signin`;
}

window.handleLogin = handleLogin;
function showSection(id) {
    // dono section hide kar do
    document.getElementById('about').style.display = 'none';
    document.getElementById('help').style.display = 'none';

    // sirf clicked wala show karo
    document.getElementById(id).style.display = 'block';

    // smooth scroll us section pe
    document.getElementById(id).scrollIntoView({ behavior: 'smooth' });
}

// global access ke liye
window.showSection = showSection;
