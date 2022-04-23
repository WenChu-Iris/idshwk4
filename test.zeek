event http_reply(c: connection, version: string, code: count, reason: string){
    
    SumStats::observe("http_response", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
    
    if(code == 404)
    {
        SumStats::observe("http_response_404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
    }

}

event zeek_init()
{
    local reducer1=SumStats::Reducer($stream="http_response", $apply=set(SumStats::SUM, SumStats::UNIQUE));

    local reducer2=SumStats::Reducer($stream="http_response_404", $apply=set(SumStats::SUM, SumStats::UNIQUE));
    
    SumStats::create([$name="find_scaner", 
                      $epoch=10min, 
                      $reducers=set(reducer1, reducer2), 
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result)=
                        {
                            local r1=result["http_response"];
                            local r2=result["http_response_404"];
                            local ratio1:double=r2$sum/r1$sum;
                            local ratio2:double=r2$unique/r2$sum;
                            
                            if(r2$sum>2 && ratio1>0.2 && ratio2>0.5)
                            {
                                
                                print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, r2$sum, r2$unique);
                            }
                        }
                     ]);

}
