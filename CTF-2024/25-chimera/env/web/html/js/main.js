window.addEventListener("load", function () {
  document.querySelector(".preloader").classList.add("opacity-0");
  setTimeout(function () {
    document.querySelector(".preloader").style.display = "none";
  }, 1000);
});

const nav = document.querySelector(".navbar-item"),
  navList = nav.querySelectorAll("li"),
  totalNavList = navList.length,
  allSection = document.querySelectorAll(".section"),
  totalSection = allSection.length;

for (let i = 0; i < totalNavList; i++) {
  const a = navList[i].querySelector("a");
  a.addEventListener("click", function () {
    for (let j = 0; j < totalNavList; j++) {
      navList[j].querySelector("a").classList.remove("active");
    }
    this.classList.add("active");
    nav.classList.add("close");
  });
}

window.addEventListener("scroll", () => {
  let fromTop = window.scrollY;
  navListAnchor = nav.querySelectorAll("a");
  navListAnchor.forEach((link) => {
    let section = document.querySelector(link.hash);
    if (
      section.offsetTop <= fromTop &&
      section.offsetTop + section.offsetHeight > fromTop
    ) {
      link.classList.add("active");
    } else {
      link.classList.remove("active");
    }
  });
});

if (window.innerWidth < 1200) {
  burger = document.querySelector(".menu-btn");
  burger.addEventListener("click", function () {
    nav.classList.toggle("close");
  });
}

var submitted = false;

function validateName() {
  var name = document.getElementById("name").value;
  if (!name.match(/^[a-zA-Z0-9\s]+$/)) {
    alert("Please enter a valid name!");
    return false;
  }
  return true;
}

function validateEmail() {
  var name = document.getElementById("email").value;
  if (!name.match(/^[A-Za-z\.\-[0-9]*[@][A-Za-z0-9]*[\.][a-z]{2,6}$/)) {
    alert("Please enter valid email!");
    return false;
  }
  return true;
}

function resetForm() {
  document.getElementById("contact-form").reset();
  console.log("Form has been reset.");
}

function validateForm() {
  if (!validateName() || !validateEmail()) {
    return false;
  } else {
    submitted = true;
    var thankyou =
      "Your message has been sent successfully. Thank you for contacting me.";
    document.getElementById("success").append(thankyou);
    return true;
  }
}
