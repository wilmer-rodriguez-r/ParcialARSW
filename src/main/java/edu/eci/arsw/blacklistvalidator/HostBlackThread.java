package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicInteger;

public class HostBlackThread extends Thread{

    private HostBlacklistsDataSourceFacade skds;
    private int start;
    private int end;
    private LinkedList<Integer> blackListOcurrences;
    private AtomicInteger ocurrencesCount;
    private AtomicInteger checkedListsCount;
    private String ipaddress;

    public HostBlackThread(HostBlacklistsDataSourceFacade skds, int start, int end, LinkedList<Integer> blackListOcurrences, AtomicInteger ocurrencesCount, AtomicInteger checkedListsCount,String ipaddress) {
        this.skds = skds;
        this.start = start;
        this.end = end;
        this.blackListOcurrences = blackListOcurrences;
        this.ocurrencesCount = ocurrencesCount;
        this.ipaddress = ipaddress;
        this.checkedListsCount = checkedListsCount;
    }
    @Override
    public void run() {
        for (int i=start;i<end && ocurrencesCount.get()<HostBlackListsValidator.BLACK_LIST_ALARM_COUNT;i++){
            checkedListsCount.addAndGet(1);
            if (skds.isInBlackListServer(i, ipaddress)){
                synchronized (blackListOcurrences) {
                    blackListOcurrences.add(i);
                }
                ocurrencesCount.addAndGet(1);
            }
        }
    }
}
