const defaultTop = -200;
const defaultBottom = 200;

let skillElements;
let inViewClass = "in-view";
let outOfViewClass = "out-of-view";
let inView = false;

// Set things up
window.addEventListener(
  "load",
  (event) => {
    skillElements = document.querySelector(".skills");
    createObserver();
  },
  false,
);


// Create the observer
function createObserver() {
  let observer;

  let options = {
    rootMargin: "55px",
    threshold: 1,
  };

  observer = new IntersectionObserver(handleIntersect, options);
  observer.observe(skillElements);
}

// Handle the intersection
function handleIntersect(entries, observer) {
  entries.forEach((entry) => {
    if (entry.isIntersecting) {
      entry.target.classList.add(inViewClass);
      entry.target.classList.remove(outOfViewClass);
      inView = true;
    } else {
      entry.target.classList.add(outOfViewClass);
      entry.target.classList.remove(inViewClass);
      inView = false;
    }

      entry.isIntersecting ? observer.unobserve(entry.target) : null;
  });
}






