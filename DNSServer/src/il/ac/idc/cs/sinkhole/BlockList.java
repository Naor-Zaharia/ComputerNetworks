package il.ac.idc.cs.sinkhole;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;

public class BlockList {

    HashSet<String> m_BlockListHashSet;

    // BlockList Constructor
    public BlockList(String i_BlockListFile) {
        this.m_BlockListHashSet = new HashSet<String>();
        loadBlockListFileToMempry(i_BlockListFile);
    }

    // Load blocklist data to memory (HashSet Collection)
    private void loadBlockListFileToMempry(String i_BlockListFile) {
        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader(i_BlockListFile));
            String currentLine;
            try {
                while ((currentLine = bufferedReader.readLine()) != null) {
                    this.m_BlockListHashSet.add(currentLine);
                }
            } catch (IOException i_E) {
                System.err.println("Had issues to load blocklist to memory");
            }
        } catch (FileNotFoundException i_E) {

        }
    }

    // Check if site Address is in the collection
    public boolean IsInBlockList(String i_SiteAddress) {
        return m_BlockListHashSet.contains(i_SiteAddress);
    }

    // Get BlockList
    public HashSet<String> GetBlockList() {
        return m_BlockListHashSet;
    }

    // Remove Address from collection
    public void RemoveFromBlockList(String i_SiteAddress) {
        m_BlockListHashSet.remove(i_SiteAddress);
    }

    // Get collection iterator
    public Iterator<String> GetBlockListIterator() {
        return m_BlockListHashSet.iterator();
    }

}
