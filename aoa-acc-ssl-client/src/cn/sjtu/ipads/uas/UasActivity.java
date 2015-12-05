package cn.sjtu.ipads.uas;

import android.app.Activity;
import android.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;

public class UasActivity extends Activity
{
  private UasTransport m_uas_tra;

  /** Called when the activity is first created. */
  @Override
  public void onCreate(Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.main);

    m_uas_tra = new UasTransport(this);

    if (m_uas_tra != null) {
      m_uas_tra.transport_start();
    }
  }
}
