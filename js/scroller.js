// Scroll to page section
const scroll = (function () {
  let navLinks = document.querySelectorAll('.nav-link');
  let nav = document.querySelectorAll('nav');
  let navList = document.querySelectorAll('li');
  
  navLinks.forEach(link => {
    link.addEventListener('click', function (e) {
      e.preventDefault();
      let id = this.getAttribute('href');
      let section = document.querySelector(id);
      let sectionPosition = section.offsetTop;
      let navHeight = nav[0].offsetHeight;

      /**
       * Remove active class from all sections
       * Add active class to the clicked section, to highlight and remove from others
       * Scroll to the clicked section with a smooth behavior
       */
      for (let i = 0; i < navList.length; i++) {
        // Create section object from the clicked link
        let activeSection = navList[i] === this.parentElement;
        // Check if the section is active. If so, add active class to the section
        // Otherwise, remove the active class from the section
        if (activeSection) {
          navList[i].classList.add('active');
        } else {
          navList[i].classList.remove('active');
        }
      }

      // Scroll to the clicked section with a smooth behavior
      window.scrollTo({
        top: sectionPosition - navHeight,
        behavior: 'smooth'
      });
    }, false);
  });
})();  // IIFE