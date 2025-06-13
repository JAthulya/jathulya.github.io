document.addEventListener("DOMContentLoaded", function () {
    const searchInput = document.getElementById("search-input");
    const searchResults = document.getElementById("search-results");
  
    fetch("/search.json")
      .then(response => response.json())
      .then(data => {
        const idx = lunr(function () {
          this.field("title");
          this.field("content");
          this.ref("url");
  
          data.forEach(function (doc) {
            this.add(doc);
          }, this);
        });
  
        searchInput.addEventListener("input", function () {
          const query = this.value.trim();
          searchResults.innerHTML = "";
  
          if (!query) return;
  
          const results = idx.search(query + "~1");;
          if (results.length > 0) {
            results.forEach(function (result) {
              const item = data.find(d => d.url === result.ref);
              const li = document.createElement("li");
              li.innerHTML = `<a href="${item.url}">${item.title}</a>`;
              searchResults.appendChild(li);
            });
          } else {
            searchResults.innerHTML = "<li>No results found</li>";
          }
        });
      });
  });
  