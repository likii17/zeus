from bs4 import BeautifulSoup

with open("att&ck_matrix.html") as f:
	html_content = f.read()

soup = BeautifulSoup(html_content, 'html.parser')

# Find all divs with class 'supertechniquecell'
supertechnique_cells = soup.find_all('div', class_='supertechniquecell')

# Iterate through each supertechniquecell div
for cell in supertechnique_cells:
    # Extract the text inside the div, convert to lowercase for comparison
    technique_name = cell.get_text(strip=True)

    cell.insert_before(r"<div {% if ('" + technique_name.strip().split("(")[0].split("&")[0] + "' in keys) %} style='background-color:rgba(180,207,236,0.8)!important' {% endif %}")

# Print the modified HTML content
with open("att&ck_updated.html", "w") as f:
	f.write(soup.prettify().replace("""%}
                 <div class=""","%} class="))