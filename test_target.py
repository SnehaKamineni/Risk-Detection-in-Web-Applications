from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def home():

    return """
    <!DOCTYPE html>

    <html>

    <head>

        <title>
            Test Website
        </title>

    </head>

    <body>

        <h1>
            Test Web Application
        </h1>

        <p>
            This application is used only for
            authorized security testing.
        </p>

        <form
            action="/search"
            method="GET"
        >

            <input
                type="text"
                name="query"
                placeholder="Search"
            >

            <button type="submit">

                Search

            </button>

        </form>

    </body>

    </html>
    """


@app.route("/search")
def search():

    query = request.args.get("query", "")

    # Intentionally vulnerable for local authorized
    # OWASP ZAP testing.
    return f"""
    <!DOCTYPE html>

    <html>

    <head>

        <title>
            Search Results
        </title>

    </head>

    <body>

        <h2>
            Search Results
        </h2>

        <p>
            You searched for: {query}
        </p>

        <a href="/">
            Home
        </a>

    </body>

    </html>
    """


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False
    )