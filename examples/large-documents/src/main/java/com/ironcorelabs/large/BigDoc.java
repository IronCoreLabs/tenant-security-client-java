package com.ironcorelabs.large;

public class BigDoc {
    public String mainDocId;
    public String title;
    public String description;
    public SubDoc[] subDocs;

    public BigDoc() {
    }

    public BigDoc(String mainDocId, String title, String description, SubDoc[] subDocs) {
        this.mainDocId = mainDocId;
        this.title = title;
        this.description = description;
        this.subDocs = subDocs;
    }
}
