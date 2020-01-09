package retirement;

public class Retirement {

	//身份证号
	private String IDnumber;
	
	//单位编号
	private String Unitnumber;

	//批次号
	private String Lotnumber;
	
	//通过退休审批时间
	private String Approvaltime;
	
	//人员姓名
	private String Username;
	
	//参保地行政区划代码
	private String Entitycode;
	
	//单位名称
	private String Unitname;

	public String getIDnumber() {
		return IDnumber;
	}

	public void setIDnumber(String iDnumber) {
		IDnumber = iDnumber;
	}

	public String getUnitnumber() {
		return Unitnumber;
	}

	public void setUnitnumber(String unitnumber) {
		Unitnumber = unitnumber;
	}

	public String getLotnumber() {
		return Lotnumber;
	}

	public void setLotnumber(String lotnumber) {
		Lotnumber = lotnumber;
	}

	public String getApprovaltime() {
		return Approvaltime;
	}

	public void setApprovaltime(String approvaltime) {
		Approvaltime = approvaltime;
	}

	public String getUsername() {
		return Username;
	}

	public void setUsername(String username) {
		Username = username;
	}

	public String getEntitycode() {
		return Entitycode;
	}

	public void setEntitycode(String entitycode) {
		Entitycode = entitycode;
	}

	public String getUnitname() {
		return Unitname;
	}

	public void setUnitname(String unitname) {
		Unitname = unitname;
	}

	@Override
	public String toString() {
		return "Retirement [IDnumber=" + IDnumber + ", Unitnumber=" + Unitnumber + ", Lotnumber=" + Lotnumber
				+ ", Approvaltime=" + Approvaltime + ", Username=" + Username + ", Entitycode=" + Entitycode
				+ ", Unitname=" + Unitname + "]";
	}
	public static void main(String[] args) {
		System.out.println("Test..");
	}
	
}
