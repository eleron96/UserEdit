const sidebar = document.querySelector('.sidebar');
const content = document.querySelector('.content');
const toggleBtn = document.querySelector('.toggle-btn');
const userHamburgerMenu = document.querySelector('.user-hamburger-menu');
const dropdownMenu = document.querySelector('.dropdown-menu');

toggleBtn.addEventListener('click', () => {
  sidebar.classList.toggle('collapsed');
  content.classList.toggle('collapsed');
});

userHamburgerMenu.addEventListener('click', () => {
  dropdownMenu.classList.toggle('active');
});


function toggleModel() {
    const container = document.querySelector('.container');
    if (container.style.display === 'none' || container.style.display === '') {
        container.style.display = 'block';
    } else {
        container.style.display = 'none';
    }
}
