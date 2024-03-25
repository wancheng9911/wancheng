# 基于UDP(snmp)协议实现数据监听

​	snmp协议隶属于UDP协议中的一种,多半应用于网管系统,此处场景应用在需接受设备告警信息

## 配置类

```java
/**
 * snmp配置类
 */
@Component
@ConfigurationProperties(prefix = "snmp.trap")
@Data
public class SnmpConfig {

    /**
     * 监听地址
     */
    private String address;
    /**
     * 团体名
     */
    private String community;
    /**
     * 线程数
     */
    private Integer threadNum;
    /**
     * 监听端口
     */
    private Integer listenPort;

}
```

```yml
snmp:
  trap:
    address: "0.0.0.0"
    listenPort: 30099
    community: "IPTV4.0"
    threadNum: 200
```

## 监听启动类

```java
/**
* 继承ApplicationRunner,服务启动完成之后自动启动监听端口,开始监听
**/
@Component
public class TrapThirdListen implements ApplicationRunner {


    @Resource
    private SnmpConfig snmpConfig;

    @Resource
    private SnmpService snmpSv;


    /**
     * 开启snmp监听服务
     */
    @Override
    public void run(ApplicationArguments args) {
        SnmpTrapHandler handler = new SnmpTrapHandler();
        handler.start(snmpConfig, snmpSv);
    }
}
```

## 初始化/数据解析

```java
	/**
     * 初始化
     */
    public void init(SnmpConfig snmpConfig) {
        //1、初始化多线程消息转发类
        ThreadPool threadPool = ThreadPool.create("SnmpTrap", snmpConfig.getThreadNum());
        MessageDispatcher messageDispatcher = new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());
        //其中要增加三种处理模型。如果snmp初始化使用的是Snmp(TransportMapping<? extends Address> transportMapping) ,就不需要增加
        messageDispatcher.addMessageProcessingModel(new MPv1());
        messageDispatcher.addMessageProcessingModel(new MPv2c());
        OctetString localEngineID = new OctetString(MPv3.createLocalEngineID());
        USM usm = new USM(SecurityProtocols.getInstance().addDefaultProtocols(), localEngineID, 0);
        UsmUser user = new UsmUser(new OctetString("SNMP3"), AuthSHA.ID, new OctetString("authPassword"),
                PrivAES128.ID, new OctetString("privyPassword"));
        usm.addUser(user.getSecurityName(), user);
        messageDispatcher.addMessageProcessingModel(new MPv3(usm));
        //2、创建transportMapping
        TransportMapping<?> transportMapping;
        try {
            //本地设置Trap接收方地址
            String ipAddress = "udp:" + snmpConfig.getAddress() + "/" + snmpConfig.getListenPort();
            UdpAddress updAdder = (UdpAddress) GenericAddress.parse(System.getProperty("snmp4j.listenAddress", ipAddress));
            transportMapping = new DefaultUdpTransportMapping(updAdder);
            //3、正式创建snmp
            snmp = new Snmp(messageDispatcher, transportMapping);
            //开启监听
            snmp.listen();
            log.info("初始化完成,监听地址为:{}", ipAddress);
        } catch (IOException e) {
            log.error("初始化transportMapping失败:{}", e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 开始监听trap
     */
    public void start(SnmpConfig snmpConfig, SnmpService snmpSv) {
        this.init(snmpConfig);
        //一定要将当前对象添加至commandResponderListeners中
        snmp.addCommandResponder(this);
        snmpService = snmpSv;
        log.info("开始监听trap信息----------------------");
    }

    /**
     * 处理信息方法
     */
    @Override
    public void processPdu(CommandResponderEvent event) {
        Integer version = null;
        String community = null;
        if (event.getPDU().getType() == PDU.V1TRAP) {
            version = SnmpConstants.version1 + 1;
            community = new String(event.getSecurityName());
        } else if (event.getPDU().getType() == PDU.TRAP) {
            if (event.getSecurityModel() == 2) {
                version = SnmpConstants.version2c + 1;
                community = new String(event.getSecurityName());
            } else {
                version = SnmpConstants.version3;
            }
        }
        //处理告警信息
        if (event.getPDU() != null) {
            Vector<VariableBinding> recVbs = (Vector<VariableBinding>) event.getPDU().getVariableBindings();
            ArrayList<SnmpDto> snmpDtoArrayList = new ArrayList<>();
            for (int i = 0; i < recVbs.size(); i++) {
                VariableBinding recVb = recVbs.elementAt(i);
                snmpDtoArrayList.add(new SnmpDto(recVb.getOid().toString(), recVb.getVariable().toString()));
//                log.info("接收到的trap信息：发送来源=" + event.getPeerAddress() + ",snmp版本=" + version + ",团体名=" + community + ", 携带的变量=Oid:" + recVb.getOid() + "---------" + recVb.getVariable().toString());
            }
            snmpService.disposeAlarmInformation(event.getPeerAddress().toString(), version, community, snmpDtoArrayList);
        }
    }
```

## 测试案例

```java
try {
            //Create Transport Mapping
            TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
            transport.listen();
            //Create Target
            CommunityTarget comtarget = new CommunityTarget();
            comtarget.setCommunity(new OctetString("IPTV4.0"));
            comtarget.setVersion(SnmpConstants.version2c);
            //设置监听地址以及端口
//            comtarget.setAddress(new UdpAddress("220.162.241.65" + "/" + 45021));
            comtarget.setAddress(new UdpAddress("iptv40.tvfjte.min" + "/" + 45001));
//            comtarget.setAddress(new UdpAddress("127.0.0.1" + "/" + 30099));
            comtarget.setRetries(2);
            comtarget.setTimeout(5000);
            //Create PDU for V2
            PDU pdu = new PDU();

            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.1"), new OctetString("20240321165405")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.2"), new OctetString("2024-03-21 16:54:05")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.3"), new OctetString("JYH-1F-FH-CDN-CSD01")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.4"), new OctetString("SS")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.5"), new OctetString("127.0.0.1")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.6"), new OctetString("JYH-1F-FH-CDN-CSD01")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.7"), new OctetString("四级")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.8"), new OctetString("1.3.6.1.4.1.1943.1.2.1")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.9"), new OctetString("424-279-00-000101")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.10"), new OctetString("接口异常，系统上报该告警。")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.11"), new OctetString("接口异常")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.12"), new OctetString("接口异常")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.13"), new OctetString("接口异常")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.14"), new OctetString("接口异常 ")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.15"), new OctetString("可能业务受影响")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.17"), new OctetString("【IPTV4.0】高清_IPTV4.0_saas_告警")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.18"), new Integer32(1)));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.1943.1.2.1.12.19"), new Integer32(1)));
            //设置PDU类型
            pdu.setType(PDU.NOTIFICATION);

            //Send the PDU
            Snmp snmp = new Snmp(transport);
            snmp.send(pdu, comtarget);
            snmp.close();
        } catch (Exception e) {
            log.error("Exception Message = " + e.getMessage());
        }
```

